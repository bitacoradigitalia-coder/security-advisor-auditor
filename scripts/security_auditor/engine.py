"""Limited static triage; results are candidates, never exploit confirmation."""
import ast
import hashlib
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

from .safeio import no_links, read_bounded, repository_files
from .scanners import capabilities

LANGUAGES = {'.py': 'Python', '.js': 'JavaScript', '.jsx': 'JavaScript', '.ts': 'TypeScript',
             '.tsx': 'TypeScript', '.go': 'Go', '.rs': 'Rust', '.java': 'Java', '.php': 'PHP',
             '.rb': 'Ruby', '.cs': 'C#', '.swift': 'Swift', '.kt': 'Kotlin', '.sh': 'Shell',
             '.ps1': 'PowerShell', '.tf': 'Terraform', '.astro': 'Astro'}
TEXT = set(LANGUAGES) | {'.md', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.env',
                              '.txt', '.html', '.css', '.xml', '.sql', '.lock', '.conf'}
MANIFESTS = {'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
             'requirements.txt', 'pyproject.toml', 'poetry.lock', 'uv.lock', 'go.mod',
             'go.sum', 'Cargo.toml', 'Cargo.lock', 'Gemfile', 'composer.json', 'pom.xml'}
PHASE_TITLES = [
    'Repository reconnaissance', 'Trust boundaries', 'Authentication', 'Authorization',
    'Resource and tenant isolation', 'Business logic', 'Token and secret handling',
    'Input validation and injection', 'Concurrency and race conditions',
    'Abuse and denial of service', 'External integrations', 'Data integrity and privacy',
    'File handling and uploads', 'Cryptography applied', 'API surface (REST, GraphQL, gRPC)',
    'Client security (web, mobile, desktop)', 'Dependency review and supply chain',
    'CI/CD and pipelines', 'Cloud, containers, and infrastructure',
    'Deployment, headers, and transport', 'Scalability and architecture advisory']
SECRET_PATTERNS = [
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?'
               r'(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\Z)'),
]
ASSIGNMENT = re.compile(r'''(?i)\b(?:password|passwd|api[_-]?key|secret|access[_-]?token)\b\s*[:=]\s*["']([^"'\r\n]{16,})["']''')


def secret_spans(text):
    spans = [(m.start(), m.end()) for p in SECRET_PATTERNS for m in p.finditer(text)]
    for m in ASSIGNMENT.finditer(text):
        value = m.group(1)
        if not any(x in value.lower() for x in ('example', 'placeholder', 'changeme', '${', '<redacted>', 'synthetic')):
            spans.append((m.start(1), m.end(1)))
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]: merged[-1][1] = max(end, merged[-1][1])
        else: merged.append([start, end])
    return merged


def redact(text):
    spans = sorted(secret_spans(str(text)))
    # Merge overlaps (e.g. a provider token inside a secret assignment).
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]: merged[-1][1] = max(end, merged[-1][1])
        else: merged.append([start, end])
    text = str(text)
    for start, end in reversed(merged): text = text[:start] + '[REDACTED]' + text[end:]
    return text


def scrub(value):
    if isinstance(value, str): return redact(value)
    if isinstance(value, list): return [scrub(v) for v in value]
    if isinstance(value, dict): return {redact(k): scrub(v) for k, v in value.items()}
    return value


def commit_id(root):
    executable = shutil.which('git')
    if not executable: return None
    try:
        # rev-parse neither runs hooks nor builds the repository.
        result = subprocess.run([executable, '-c', 'core.fsmonitor=false', '-C', str(root),
                                 'rev-parse', '--verify', 'HEAD'], capture_output=True, timeout=5)
        value = result.stdout.decode('ascii', errors='ignore').strip()
        return value if result.returncode == 0 and re.fullmatch(r'[0-9a-f]{40,64}', value) else None
    except (OSError, subprocess.TimeoutExpired): return None


def candidate(path, line, title, cwe, phase, explanation, remediation, confidence='medium'):
    return {'id': '', 'title': title, 'type': 'probable_weakness', 'cwe': cwe,
            'severity': 'medium', 'severity_reason': 'Impacto potencial; alcance y alcanzabilidad pendientes',
            'priority': 'investigate', 'confidence': confidence, 'phase': phase,
            'location': {'file': path, 'line_start': line, 'line_end': line, 'function': None},
            'description': explanation, 'preconditions': ['Confirmar que entrada no confiable alcanza esta operación'],
            'evidence': {'kind': 'static_signal', 'summary': 'Señal estática; código fuente omitido para evitar secretos'},
            'verification': {'status': 'not_verified', 'executed': False},
            'impact': explanation, 'remediation': remediation,
            'references': ['https://cwe.mitre.org/data/definitions/' + cwe.split('-')[1] + '.html']}


def python_candidates(text, name, limitations):
    try: tree = ast.parse(text, filename='<untrusted>')
    except (SyntaxError, RecursionError, MemoryError):
        limitations.append('AST no disponible: ' + name); return []
    findings = []
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names: aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names: aliases[alias.asname or alias.name] = (node.module or '') + '.' + alias.name

    def call_name(node):
        if isinstance(node, ast.Name): return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute): return call_name(node.value) + '.' + node.attr
        return ''

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call): continue
        func = call_name(node.func)
        issue = None
        if func in ('eval', 'exec', 'builtins.eval', 'builtins.exec'):
            issue = ('Evaluación dinámica', 'CWE-95', 8, 'Posible ejecución de expresiones de entrada',
                     'Sustituir evaluación por parser de datos; trazar origen y validar esquema')
        elif func in ('subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_call',
                       'subprocess.check_output') and any(k.arg == 'shell' and
                        isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            issue = ('Comando con shell=True', 'CWE-78', 8, 'Posible inyección si el comando contiene entrada externa',
                     'Usar lista de argumentos y shell=False; validar cada argumento')
        elif func in ('os.system', 'os.popen'):
            issue = ('Comando interpretado por shell', 'CWE-78', 8, 'Posible inyección de comandos',
                     'Usar ejecución sin shell con argumentos validados')
        elif func in ('pickle.load', 'pickle.loads'):
            issue = ('Deserialización pickle', 'CWE-502', 8, 'Carga peligrosa si los datos provienen de terceros',
                     'Usar formato de datos sin ejecución o restringir a datos confiables')
        elif any(k.arg == 'verify' and isinstance(k.value, ast.Constant) and k.value.value is False
                 for k in node.keywords) and func.startswith(('requests.', 'httpx.')):
            issue = ('Verificación TLS desactivada', 'CWE-295', 14, 'Posible suplantación de servidor TLS',
                     'Activar validación de certificados y configurar CA confiable')
        if issue: findings.append(candidate(name, node.lineno, *issue))
    return findings


def analyze(root, max_file_bytes=1_000_000, max_files=10000, max_total_bytes=20_000_000,
            mode='QUICK', max_depth=64, max_seconds=30, max_memory_bytes=128_000_000,
            max_findings=10000, max_ast_nodes=50000, max_call_depth=4):
    from .contextual import analyze_python
    from .verification import enrich_candidate
    if mode not in ('QUICK', 'STANDARD', 'DEEP'):
        raise ValueError('Modo inválido')
    if min(max_file_bytes, max_files, max_total_bytes, max_seconds, max_memory_bytes,
           max_findings, max_ast_nodes, max_call_depth) <= 0 or max_depth < 0:
        raise ValueError('Los límites deben ser positivos')
    deadline = time.perf_counter() + max_seconds
    root = no_links(root)
    limitations = ['Análisis estático limitado: sin ejecución del objetivo, pruebas activas ni consultas de advisories',
                   'Historial Git, archivos binarios y directorios generados no analizados',
                   'Prompt injection: contenido leído como datos; comportamiento de modelos no probado',
                   'Sin defensa contra modificación concurrente hostil del sistema de archivos; usar snapshot aislado']
    languages = Counter(); files = []; manifests = []; signals = []; findings = []
    total = read_count = 0; types = set(); frameworks = set(); ast_executed = False
    for path in repository_files(root, limitations, max_files=max_files, max_depth=max_depth, deadline=deadline):
        if time.perf_counter() > deadline:
            limitations.append('Límite de tiempo alcanzado; archivos restantes sin analizar'); break
        if len(findings) >= max_findings:
            limitations.append('Límite de hallazgos alcanzado; archivos restantes sin analizar'); break
        name = path.relative_to(root).as_posix(); files.append(name)
        if path.suffix.lower() in LANGUAGES: languages[LANGUAGES[path.suffix.lower()]] += 1
        if path.name in MANIFESTS: manifests.append(name)
        if path.suffix.lower() == '.tf' or path.name.startswith('Dockerfile'):
            types.add('infrastructure'); signals.append({'file': name, 'kind': 'infrastructure'})
        if path.suffix.lower() not in TEXT and path.name not in ('Dockerfile', 'Gemfile') and not path.name.startswith('.env'):
            limitations.append('Formato no leído: ' + name); continue
        try: data = read_bounded(path, min(max_file_bytes, max_total_bytes - total))
        except (ValueError, OSError): limitations.append('Archivo omitido por límite/acceso: ' + name); continue
        total += len(data)
        if b'\x00' in data: limitations.append('Binario omitido: ' + name); continue
        try: text = data.decode('utf-8-sig')
        except UnicodeDecodeError: limitations.append('Codificación no UTF-8: ' + name); continue
        read_count += 1
        for start, _ in secret_spans(text):
            findings.append(candidate(name, text.count('\n', 0, start) + 1,
                                      'Posible secreto embebido', 'CWE-798', 7,
                                      'Patrón de credencial; validez y exposición pendientes',
                                      'Verificar exposición; revocar si procede y mover a gestión de secretos', 'low'))
        if path.suffix == '.py':
            findings.extend(analyze_python(text, name, limitations, mode=mode,
                max_nodes=max_ast_nodes, max_memory_bytes=max_memory_bytes,
                max_call_depth=max_call_depth, deadline=deadline)); ast_executed = True
        if path.suffix in ('.js', '.jsx', '.ts', '.tsx', '.html', '.astro'):
            for m in re.finditer(r'dangerouslySetInnerHTML|\.innerHTML\s*=', text):
                findings.append(candidate(name, text.count('\n', 0, m.start()) + 1,
                                          'HTML dinámico sin contexto confirmado', 'CWE-79', 16,
                                          'Posible XSS si no hay sanitización de datos externos',
                                          'Trazar origen; escapar o sanitizar con política explícita', 'low'))
        if path.name == 'package.json':
            try:
                manifest = json.loads(text)
                deps = {**manifest.get('dependencies', {}), **manifest.get('devDependencies', {})}
                for framework in ('react', 'next', 'astro', 'vue', 'express', 'fastify', 'koa'):
                    if framework in deps: frameworks.add(framework)
            except (ValueError, TypeError, AttributeError): limitations.append('Manifest no válido: ' + name)
        if path.suffix == '.py':
            for fw in ('flask', 'django', 'fastapi'):
                if re.search(r'\b(?:from|import)\s+' + fw + r'\b', text): frameworks.add(fw)
        if path.suffix in ('.html', '.astro', '.jsx', '.tsx') or frameworks & {'react', 'next', 'vue', 'astro'}:
            types.add('web')
        if re.search(r'@(?:app|router)\.(?:get|post|put|delete)\b|app\.(?:get|post|use)\s*\(', text):
            types.add('api'); signals.append({'file': name, 'kind': 'route_candidate'})
        if path.suffix in ('.sh', '.ps1') or 'argparse' in text:
            types.add('cli'); signals.append({'file': name, 'kind': 'cli_candidate'})
    findings.sort(key=lambda f: (f['location']['file'], f['location']['line_start'], f['cwe']))
    if len(findings) > max_findings:
        limitations.append('Límite de hallazgos alcanzado; resultados truncados')
        findings = findings[:max_findings]
    commit = commit_id(root)
    for finding in findings:
        if 'status' not in finding: enrich_candidate(finding)
        identity = (finding['location']['file'], finding['location']['function'],
                    finding['location']['line_start'], finding.get('category'), finding['cwe'])
        finding['id'] = 'SAA-' + str(int.from_bytes(hashlib.sha256(repr(identity).encode()).digest()[:12], 'big'))
        finding['commit'] = commit
    coverage = []
    for phase, title in enumerate(PHASE_TITLES, 1):
        partial = phase in (1, 7, 8, 14, 16, 17, 19) or mode != 'QUICK' and phase in (4, 5, 11, 13)
        coverage.append({'phase': phase, 'title': title,
                         'status': 'automated_partial' if partial else 'not_evaluated',
                         'reason': 'Inventario/señales limitadas; requiere revisión del agente' if partial else
                                   'Revisión contextual pendiente; no se infiere no aplicable',
                         'finding_ids': [f['id'] for f in findings if f['phase'] == phase]})
    tools = capabilities()
    for tool in tools:
        if tool['name'] == 'python-ast' and ast_executed: tool['status'] = 'executed'
        if tool['name'] == 'git' and tool['status'] != 'unavailable':
            tool['status'] = 'executed' if commit else 'attempted_no_commit'
        if tool['status'] == 'unavailable': limitations.append('Herramienta opcional no disponible: ' + tool['name'])
    return scrub({'schema_version': '2.0', 'generated_at': datetime.now(timezone.utc).isoformat(),
                  'project': {'name': root.name, 'commit': commit, 'working_tree': 'not_evaluated',
                              'types': sorted(types) or ['unknown'], 'languages': dict(languages),
                              'frameworks': sorted(frameworks), 'files': sorted(files), 'files_read': read_count,
                              'bytes_read': total, 'manifests': sorted(manifests), 'attack_surfaces': signals,
                              'architecture': 'Inventario automático; flujos y límites de confianza pendientes'},
                  'scope': 'Archivos locales del directorio; se incluyen cambios sin commit',
                  'methodology': 'Security Advisor Auditor: 21 fases originales',
                  'coverage': coverage, 'tools': tools, 'findings': findings, 'positive_findings': [],
                  'analysis': {'version': '2.1', 'mode': mode, 'limits': {
                      'max_file_bytes': max_file_bytes, 'max_files': max_files,
                      'max_total_bytes': max_total_bytes, 'max_depth': max_depth,
                      'max_seconds': max_seconds, 'max_memory_bytes': max_memory_bytes,
                      'max_findings': max_findings, 'max_ast_nodes': max_ast_nodes,
                      'max_call_depth': max_call_depth},
                      'memory_policy': 'Estimated input/AST allocation budget; not a hard RSS cap',
                      'time_policy': 'Cooperative deadline; parsing bounded by file/node budgets',
                      'confirmation': 'Automatic results never confirm exploitation'},
                  'limitations': limitations,
                  'references': ['https://owasp.org/www-project-application-security-verification-standard/',
                                 'https://cwe.mitre.org/']})
