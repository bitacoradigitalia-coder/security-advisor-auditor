"""Frozen trusted v2.0.1 candidate rules from Git 51a3abb; fixtures are only parsed."""
import ast

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
