#!/usr/bin/env python3
"""Offline CLI. python scripts/audit.py --help"""
import argparse
import json
from pathlib import Path
import sys
import zipfile

sys.dont_write_bytecode = True
from security_auditor.engine import analyze
from security_auditor.reporting import write_outputs, legacy_report
from security_auditor.safeio import extract_zip, read_bounded
from security_auditor.scanners import plans
from security_auditor.validation import validate_skill
from security_auditor.sources import project_source


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Security Advisor Auditor v3.0: Análisis de seguridad (estático + activo)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Análisis estático (original)
  python scripts/audit.py scan /ruta/repo --output ./informe --mode DEEP

  # Escaneo activo de URL
  python scripts/audit.py scan https://example.com --output ./informe --active

  # Escaneo con autenticación
  python scripts/audit.py scan https://example.com --output ./informe --active --session admin

  # Escaneo con Nuclei
  python scripts/audit.py scan https://example.com --output ./informe --active --nuclei

  # Fuzzing de parámetros
  python scripts/audit.py fuzz https://example.com/api --param id --output ./fuzz-results

  # Explotación controlada (requiere permiso)
  python scripts/audit.py exploit https://example.com/api?id=1 --vuln sqli --permission-file permissions.json

  # Gestión de Bug Bounty
  python scripts/audit.py bugbounty add-program --name "Example Inc" --scope example.com
  python scripts/audit.py bugbounty add-finding --program "Example Inc" --file ./informe/audit.json

  # Reportes avanzados
  python scripts/audit.py report ./informe/audit.json --output ./reporte-final --format html

  # Validación de skill
  python scripts/audit.py validate-skill .

  # Herramientas disponibles
  python scripts/audit.py tools
        '''
    )
    
    commands = parser.add_subparsers(dest='command', required=True)
    
    # ========================================================================
    # SCAN COMMAND - Análisis completo (estático + activo)
    # ========================================================================
    scan = commands.add_parser('scan', help='Análisis completo: estático y/o activo')
    scan.add_argument('target', type=str, help='Ruta del repositorio o URL del objetivo')
    scan.add_argument('--output', type=Path, required=True, help='Directorio de salida')
    
    # Static analysis options
    scan.add_argument('--mode', choices=('QUICK', 'STANDARD', 'DEEP'), default='QUICK',
                      help='Modo de análisis estático (QUICK, STANDARD, DEEP)')
    scan.add_argument('--max-file-bytes', type=int, default=1_000_000)
    scan.add_argument('--max-files', type=int, default=10000)
    scan.add_argument('--max-total-bytes', type=int, default=20_000_000)
    scan.add_argument('--max-depth', type=int, default=64)
    scan.add_argument('--max-seconds', type=float, default=30)
    scan.add_argument('--max-memory-bytes', type=int, default=128_000_000,
                      help='Límite de memoria del subproceso parser y presupuesto estimado AST')
    scan.add_argument('--max-findings', type=int, default=10000)
    scan.add_argument('--max-ast-nodes', type=int, default=50000)
    scan.add_argument('--max-call-depth', type=int, default=4)
    scan.add_argument('--legacy-report', action='store_true', help='Exportar únicamente campos del contrato v2.0')
    
    # Active scanning options
    scan.add_argument('--active', action='store_true', help='Habilitar escaneo activo')
    scan.add_argument('--session', type=str, help='Nombre de la sesión autenticada')
    scan.add_argument('--nuclei', action='store_true', help='Ejecutar Nuclei (requiere instalación)')
    scan.add_argument('--nuclei-templates', type=str, help='Plantillas de Nuclei (ej: sqli,xss)')
    scan.add_argument('--fuzz', action='store_true', help='Habilitar fuzzing de parámetros')
    scan.add_argument('--fuzz-params', type=str, help='Parámetros a fuzzar (ej: id,user,token)')
    scan.add_argument('--scan-js', action='store_true', default=True, help='Escanear archivos JavaScript')
    scan.add_argument('--scan-forms', action='store_true', default=True, help='Escanear formularios')
    scan.add_argument('--scan-headers', action='store_true', default=True, help='Escanear headers')
    scan.add_argument('--scan-cookies', action='store_true', default=True, help='Escanear cookies')
    
    # ========================================================================
    # FUZZ COMMAND - Fuzzing de parámetros
    # ========================================================================
    fuzz = commands.add_parser('fuzz', help='Fuzzing de parámetros para detectar vulnerabilidades')
    fuzz.add_argument('target', type=str, help='URL del objetivo')
    fuzz.add_argument('--output', type=Path, required=True, help='Directorio de salida')
    fuzz.add_argument('--param', type=str, action='append', help='Parámetro a fuzzar (puede repetirse)')
    fuzz.add_argument('--params', type=str, help='Lista de parámetros separados por comas')
    fuzz.add_argument('--wordlist', type=str, help='Ruta al wordlist personalizado')
    fuzz.add_argument('--vuln-types', type=str, default='sqli,xss,ssrf,rce,lfi,idor',
                      help='Tipos de vulnerabilidades a probar (ej: sqli,xss)')
    fuzz.add_argument('--methods', type=str, default='GET,POST',
                      help='Métodos HTTP a probar (ej: GET,POST,PUT)')
    fuzz.add_argument('--session', type=str, help='Nombre de la sesión autenticada')
    fuzz.add_argument('--threads', type=int, default=5, help='Número de hilos')
    fuzz.add_argument('--timeout', type=int, default=30, help='Timeout en segundos')
    fuzz.add_argument('--delay', type=float, default=0.1, help='Retraso entre requests')
    
    # ========================================================================
    # EXPLOIT COMMAND - Explotación controlada
    # ========================================================================
    exploit = commands.add_parser('exploit', help='Explotación controlada de vulnerabilidades')
    exploit.add_argument('target', type=str, help='URL del objetivo')
    exploit.add_argument('--vuln', type=str, required=True, choices=[
        'sqli', 'xss', 'ssrf', 'rce', 'lfi', 'rfi', 'idor', 'xxe', 'csrf',
        'command-injection', 'path-traversal', 'open-redirect'
    ], help='Tipo de vulnerabilidad')
    exploit.add_argument('--param', type=str, default='', help='Parámetro vulnerable')
    exploit.add_argument('--payload', type=str, default='', help='Payload personalizado')
    exploit.add_argument('--method', type=str, default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                         help='Método HTTP')
    exploit.add_argument('--session', type=str, help='Nombre de la sesión autenticada')
    exploit.add_argument('--permission-file', type=str, required=True,
                         help='Archivo de permisos (obligatorio para explotación)')
    exploit.add_argument('--output', type=Path, help='Directorio de salida para resultados')
    exploit.add_argument('--generate-poc', action='store_true', help='Generar PoC automático')
    
    # ========================================================================
    # BUGBOUNTY COMMAND - Gestión de Bug Bounty
    # ========================================================================
    bugbounty = commands.add_parser('bugbounty', help='Gestión de programas de Bug Bounty')
    bugbounty_sub = bugbounty.add_subparsers(dest='bb_command', required=True)
    
    # Add program
    add_program = bugbounty_sub.add_parser('add-program', help='Agregar un programa de Bug Bounty')
    add_program.add_argument('--name', type=str, required=True, help='Nombre del programa')
    add_program.add_argument('--scope', type=str, required=True, help='Scope (ej: example.com,api.example.com)')
    add_program.add_argument('--rules', type=str, help='Reglas del programa')
    add_program.add_argument('--platform', type=str, choices=['hackerone', 'bugcrowd', 'intigriti', 'other'],
                             help='Plataforma de Bug Bounty')
    add_program.add_argument('--api-token', type=str, help='API token para la plataforma')
    
    # Add finding
    add_finding = bugbounty_sub.add_parser('add-finding', help='Agregar un hallazgo a un programa')
    add_finding.add_argument('--program', type=str, required=True, help='Nombre del programa')
    add_finding.add_argument('--file', type=Path, required=True, help='Archivo audit.json con hallazgos')
    add_finding.add_argument('--finding-id', type=str, help='ID específico del hallazgo')
    add_finding.add_argument('--severity', type=str, choices=['info', 'low', 'medium', 'high', 'critical'],
                              help='Severidad del hallazgo')
    
    # List programs
    list_programs = bugbounty_sub.add_parser('list-programs', help='Listar programas configurados')
    
    # List findings
    list_findings = bugbounty_sub.add_parser('list-findings', help='Listar hallazgos de un programa')
    list_findings.add_argument('--program', type=str, help='Nombre del programa (opcional)')
    
    # Generate report
    gen_report = bugbounty_sub.add_parser('generate-report', help='Generar reporte para Bug Bounty')
    gen_report.add_argument('--finding-id', type=str, required=True, help='ID del hallazgo')
    gen_report.add_argument('--format', type=str, default='markdown',
                            choices=['markdown', 'html', 'json'],
                            help='Formato del reporte')
    gen_report.add_argument('--output', type=Path, help='Archivo de salida')
    gen_report.add_argument('--platform', type=str, choices=['hackerone', 'bugcrowd', 'generic'],
                             help='Formato específico de la plataforma')
    
    # Submit to platform
    submit = bugbounty_sub.add_parser('submit', help='Enviar reporte a plataforma de Bug Bounty')
    submit.add_argument('--finding-id', type=str, required=True, help='ID del hallazgo')
    submit.add_argument('--platform', type=str, required=True, choices=['hackerone', 'bugcrowd'],
                        help='Plataforma de destino')
    submit.add_argument('--program-handle', type=str, required=True, help='Handle del programa')
    submit.add_argument('--api-token', type=str, required=True, help='API token')
    submit.add_argument('--dry-run', action='store_true', help='Simular envío sin enviar')
    
    # ========================================================================
    # AUTH COMMAND - Gestión de autenticación
    # ========================================================================
    auth = commands.add_parser('auth', help='Gestión de autenticación')
    auth_sub = auth.add_subparsers(dest='auth_command', required=True)
    
    # Add session
    add_session = auth_sub.add_parser('add-session', help='Agregar una sesión autenticada')
    add_session.add_argument('--name', type=str, required=True, help='Nombre de la sesión')
    add_session.add_argument('--cookies', type=str, help='Cookies (ej: "session=abc; auth=xyz")')
    add_session.add_argument('--headers', type=str, help='Headers (JSON)')
    add_session.add_argument('--token', type=str, help='Bearer token')
    add_session.add_argument('--username', type=str, help='Usuario para Basic Auth')
    add_session.add_argument('--password', type=str, help='Contraseña para Basic Auth')
    add_session.add_argument('--base-url', type=str, help='URL base del objetivo')
    add_session.add_argument('--auth-type', type=str, default='cookie',
                              choices=['cookie', 'bearer', 'basic', 'oauth2'],
                              help='Tipo de autenticación')
    
    # List sessions
    list_sessions = auth_sub.add_parser('list-sessions', help='Listar sesiones guardadas')
    
    # Remove session
    remove_session = auth_sub.add_parser('remove-session', help='Eliminar una sesión')
    remove_session.add_argument('--name', type=str, required=True, help='Nombre de la sesión')
    
    # OAuth2 token
    oauth_token = auth_sub.add_parser('oauth2-token', help='Obtener token OAuth2')
    oauth_token.add_argument('--token-url', type=str, required=True, help='URL del endpoint de token')
    oauth_token.add_argument('--client-id', type=str, required=True, help='Client ID')
    oauth_token.add_argument('--client-secret', type=str, required=True, help='Client secret')
    oauth_token.add_argument('--scope', type=str, help='Scope solicitado')
    oauth_token.add_argument('--grant-type', type=str, default='client_credentials',
                              help='Tipo de grant')
    
    # ========================================================================
    # REPORT COMMAND - Reportes avanzados
    # ========================================================================
    report = commands.add_parser('report', help='Generación de reportes avanzados')
    report.add_argument('input', type=Path, help='Archivo audit.json de entrada')
    report.add_argument('--output', type=Path, required=True, help='Directorio o archivo de salida')
    report.add_argument('--format', type=str, default='markdown',
                        choices=['markdown', 'html', 'pdf', 'json'],
                        help='Formato del reporte')
    report.add_argument('--template', type=str, help='Plantilla personalizada')
    report.add_argument('--include-false-positives', action='store_true', help='Incluir falsos positivos')
    report.add_argument('--severity-filter', type=str, help='Filtrar por severidad (ej: high,critical)')
    
    # ========================================================================
    # POC COMMAND - Generación de PoCs
    # ========================================================================
    poc = commands.add_parser('poc', help='Generación de Proof of Concepts')
    poc.add_argument('finding-id', type=str, required=True, help='ID del hallazgo')
    poc.add_argument('--input', type=Path, required=True, help='Archivo audit.json')
    poc.add_argument('--output', type=Path, help='Archivo de salida (default: poc_{finding-id}.py)')
    poc.add_argument('--language', type=str, default='python',
                    choices=['python', 'bash', 'curl'],
                    help='Lenguaje del PoC')
    poc.add_argument('--target', type=str, help='URL del objetivo (sobreescribe el del hallazgo)')
    
    # ========================================================================
    # Original commands (backward compatibility)
    # ========================================================================
    validate = commands.add_parser('validate-skill', help='Validar skill')
    validate.add_argument('skill', type=Path)
    
    extract = commands.add_parser('extract-zip', help='Extraer archivo ZIP')
    extract.add_argument('archive', type=Path)
    extract.add_argument('--output', type=Path, required=True)
    
    commands.add_parser('tools', help='Herramientas disponibles')
    
    # ========================================================================
    # Parse arguments and execute
    # ========================================================================
    args = parser.parse_args(argv)
    
    try:
        if args.command == 'scan':
            # Handle both file paths and URLs
            if args.target.startswith(('http://', 'https://')):
                # Active scanning for URLs
                _handle_active_scan(args)
            else:
                # Static analysis for file paths
                _handle_static_scan(args)
        
        elif args.command == 'fuzz':
            _handle_fuzzing(args)
        
        elif args.command == 'exploit':
            _handle_exploitation(args)
        
        elif args.command == 'bugbounty':
            _handle_bugbounty(args)
        
        elif args.command == 'auth':
            _handle_auth(args)
        
        elif args.command == 'report':
            _handle_report(args)
        
        elif args.command == 'poc':
            _handle_poc(args)
        
        elif args.command == 'validate-skill':
            with project_source(args.skill) as root:
                print(json.dumps(validate_skill(root), ensure_ascii=False))
        
        elif args.command == 'extract-zip':
            extract_zip(args.archive, args.output)
            print('Extracción completada en destino nuevo')
        
        elif args.command == 'tools':
            print(json.dumps(plans(), ensure_ascii=False, indent=2))
        
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        # Do not echo source data, paths or malformed JSON that might contain secrets.
        print('Operación rechazada (' + type(exc).__name__ + '). Comprueba formato, permisos, límites y destino nuevo.', file=sys.stderr)
        return 2
    
    return 0


def _handle_static_scan(args):
    """Handle static code analysis (original functionality)."""
    from pathlib import Path
    
    repository = Path(args.target)
    if not repository.is_dir():
        raise ValueError(f"El objetivo debe ser un directorio: {args.target}")
    
    data = analyze(
        repository,
        args.max_file_bytes,
        args.max_files,
        args.max_total_bytes,
        mode=args.mode,
        max_depth=args.max_depth,
        max_seconds=args.max_seconds,
        max_memory_bytes=args.max_memory_bytes,
        max_findings=args.max_findings,
        max_ast_nodes=args.max_ast_nodes,
        max_call_depth=args.max_call_depth
    )
    
    if args.legacy_report:
        data = legacy_report(data)
    
    write_outputs(data, args.output, repository)
    print(f'Informe generado; observaciones registradas: {len(data["findings"])}')


def _handle_active_scan(args):
    """Handle active scanning for URLs."""
    from pathlib import Path
    from pentesting.scanner import ActiveScanner, ScanConfig
    from pentesting.fuzzer import Fuzzer, FuzzConfig
    from pentesting.nuclei_integration import get_nuclei_runner
    from pentesting.auth import get_auth_manager
    import json
    
    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)
    
    results = {
        'target': args.target,
        'scan_results': {},
        'fuzz_results': [],
        'nuclei_results': [],
        'findings': [],
        'statistics': {}
    }
    
    # Initialize auth manager
    auth_manager = get_auth_manager()
    
    # 1. Active scanning
    if args.active:
        print(f"[*] Iniciando escaneo activo de {args.target}")
        
        scan_config = ScanConfig(
            target=args.target,
            session_name=args.session,
            scan_js=args.scan_js,
            scan_forms=args.scan_forms,
            scan_headers=args.scan_headers,
            scan_cookies=args.scan_cookies
        )
        
        scanner = ActiveScanner(scan_config)
        scan_results = scanner.scan()
        results['scan_results'] = scan_results
        
        print(f"[+] Escaneo activo completado: {len(scan_results.get('endpoints', []))} endpoints descubiertos")
    
    # 2. Fuzzing
    if args.fuzz:
        print(f"[*] Iniciando fuzzing de {args.target}")
        
        # Parse parameters
        params = []
        if args.param:
            params.extend(args.param)
        if args.params:
            params.extend(args.params.split(','))
        
        # Parse vulnerability types
        vuln_types = args.vuln_types.split(',') if args.vuln_types else []
        
        fuzz_config = FuzzConfig(
            target=args.target,
            parameters=params,
            session_name=args.session,
            detect_sqli='sqli' in vuln_types,
            detect_xss='xss' in vuln_types,
            detect_ssrf='ssrf' in vuln_types,
            detect_rce='rce' in vuln_types,
            detect_lfi='lfi' in vuln_types,
            detect_idor='idor' in vuln_types,
            detect_xxe='xxe' in vuln_types,
            max_threads=args.threads,
            timeout=args.timeout,
            delay=args.delay
        )
        
        fuzzer = Fuzzer(fuzz_config)
        fuzz_results = fuzzer.fuzz()
        results['fuzz_results'] = [r.to_dict() for r in fuzz_results]
        
        print(f"[+] Fuzzing completado: {len(fuzz_results)} pruebas, {len(fuzzer.get_vulnerable_results())} vulnerables")
    
    # 3. Nuclei scanning
    if args.nuclei:
        print(f"[*] Iniciando escaneo con Nuclei de {args.target}")
        
        try:
            nuclei_runner = get_nuclei_runner()
            
            # Parse templates
            templates = []
            if args.nuclei_templates:
                templates = args.nuclei_templates.split(',')
            
            if templates:
                nuclei_results = nuclei_runner.scan_with_templates(args.target, templates)
            else:
                nuclei_results = nuclei_runner.scan_common_vulnerabilities(args.target)
            
            results['nuclei_results'] = [r.to_dict() for r in nuclei_results]
            print(f"[+] Nuclei completado: {len(nuclei_results)} hallazgos")
        except RuntimeError as e:
            print(f"[!] Nuclei no disponible: {e}")
            results['nuclei_results'] = []
    
    # 4. Save results
    # Combine all findings
    all_findings = []
    
    # From active scan
    if 'scan_results' in results and 'vulnerabilities' in results['scan_results']:
        for vuln in results['scan_results']['vulnerabilities']:
            all_findings.append({
                'type': 'vulnerability',
                'source': 'active_scan',
                'data': vuln
            })
    
    # From fuzzing
    for fuzz_result in results['fuzz_results']:
        if fuzz_result.get('is_vulnerable'):
            all_findings.append({
                'type': 'vulnerability',
                'source': 'fuzzing',
                'data': fuzz_result
            })
    
    # From Nuclei
    for nuclei_result in results['nuclei_results']:
        all_findings.append({
            'type': 'vulnerability',
            'source': 'nuclei',
            'data': nuclei_result
        })
    
    results['findings'] = all_findings
    results['statistics'] = {
        'total_findings': len(all_findings),
        'scan_endpoints': len(results['scan_results'].get('endpoints', [])),
        'fuzz_tests': len(results['fuzz_results']),
        'fuzz_vulnerable': len([r for r in results['fuzz_results'] if r.get('is_vulnerable')]),
        'nuclei_findings': len(results['nuclei_results'])
    }
    
    # Save JSON
    json_path = args.output / 'active-scan-results.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Save summary
    summary = {
        'target': args.target,
        'scan_time': results.get('scan_results', {}).get('statistics', {}).get('scan_duration', 0),
        'statistics': results['statistics'],
        'technologies': results.get('scan_results', {}).get('technologies', []),
        'waf': results.get('scan_results', {}).get('waf'),
        'cms': results.get('scan_results', {}).get('cms')
    }
    
    summary_path = args.output / 'active-scan-summary.json'
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print(f"[+] Resultados guardados en {args.output}")
    print(f"    - {json_path}")
    print(f"    - {summary_path}")


def _handle_fuzzing(args):
    """Handle fuzzing command."""
    from pentesting.fuzzer import Fuzzer, FuzzConfig
    import json
    
    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)
    
    # Parse parameters
    params = []
    if args.param:
        params.extend(args.param)
    if args.params:
        params.extend(args.params.split(','))
    
    # Parse methods
    methods = args.methods.split(',') if args.methods else ['GET', 'POST']
    
    # Parse vulnerability types
    vuln_types = args.vuln_types.split(',') if args.vuln_types else []
    
    fuzz_config = FuzzConfig(
        target=args.target,
        parameters=params,
        wordlist=args.wordlist,
        methods=methods,
        session_name=args.session,
        detect_sqli='sqli' in vuln_types,
        detect_xss='xss' in vuln_types,
        detect_ssrf='ssrf' in vuln_types,
        detect_rce='rce' in vuln_types,
        detect_lfi='lfi' in vuln_types,
        detect_idor='idor' in vuln_types,
        detect_xxe='xxe' in vuln_types,
        max_threads=args.threads,
        timeout=args.timeout,
        delay=args.delay
    )
    
    fuzzer = Fuzzer(fuzz_config)
    results = fuzzer.fuzz()
    
    # Save results
    json_path = args.output / 'fuzz-results.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
    
    # Save summary
    summary = fuzzer.get_summary()
    summary_path = args.output / 'fuzz-summary.json'
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print(f"[+] Fuzzing completado: {len(results)} pruebas")
    print(f"[+] Vulnerables: {len(fuzzer.get_vulnerable_results())}")
    print(f"[+] Resultados guardados en {json_path}")


def _handle_exploitation(args):
    """Handle exploitation command."""
    from pentesting.exploit import ExploitManager, ExploitConfig
    from pentesting.auth import PermissionManager
    import json
    
    # Check permission file exists
    if not os.path.exists(args.permission_file):
        raise ValueError(f"Archivo de permisos no encontrado: {args.permission_file}")
    
    # Load permission manager
    perm_manager = PermissionManager(args.permission_file)
    
    # Check permission
    if not perm_manager.check_permission(args.target, args.vuln):
        raise PermissionError(
            f"Explotación de {args.vuln} en {args.target} no está permitida. "
            "Agregue permiso con: auth add-permission"
        )
    
    # Create output directory if specified
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
    
    # Configure exploitation
    exploit_config = ExploitConfig(
        target=args.target,
        vulnerability_type=args.vuln,
        parameter=args.param,
        payload=args.payload,
        method=args.method,
        session_name=args.session,
        permission_required=True,
        permission_file=args.permission_file
    )
    
    # Execute exploitation
    manager = ExploitManager(exploit_config)
    results = manager.exploit()
    
    # Save results
    if args.output:
        json_path = args.output / 'exploit-results.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
        
        print(f"[+] Resultados guardados en {json_path}")
    
    # Generate PoC if requested
    if args.generate_poc and results:
        poc_path = args.output / f'poc_{args.vuln}_{args.target.replace("https://", "").replace("http://", "").replace("/", "_")}.py'
        _generate_poc(results[0], poc_path)
        print(f"[+] PoC generado en {poc_path}")
    
    # Print summary
    successful = len([r for r in results if r.success])
    print(f"[+] Explotación completada: {successful}/{len(results)} exitosa")
    
    for result in results:
        status = "[+]" if result.success else "[-]"
        print(f"{status} {args.vuln} en {args.target}: {result.evidence or result.error}")


def _handle_bugbounty(args):
    """Handle bug bounty commands."""
    from bugbounty.manager import BugBountyManager
    from bugbounty.platforms import HackerOneIntegration, BugcrowdIntegration
    import json
    
    # Initialize manager
    manager = BugBountyManager()
    
    if args.bb_command == 'add-program':
        manager.add_program(
            name=args.name,
            scope=args.scope,
            rules=args.rules or ""
        )
        print(f"[+] Programa '{args.name}' agregado")
        
    elif args.bb_command == 'add-finding':
        # Load findings from file
        with open(args.file, 'r', encoding='utf-8') as f:
            findings = json.load(f)
        
        # Add finding
        if args.finding_id:
            # Find specific finding
            finding = next((f for f in findings.get('findings', []) if f.get('id') == args.finding_id), None)
            if finding:
                manager.add_finding(args.program, finding)
                print(f"[+] Hallazgo '{args.finding_id}' agregado al programa '{args.program}'")
            else:
                print(f"[-] Hallazgo '{args.finding_id}' no encontrado")
        else:
            # Add all findings
            for finding in findings.get('findings', []):
                manager.add_finding(args.program, finding)
            print(f"[+] {len(findings.get('findings', []))} hallazgos agregados al programa '{args.program}'")
        
    elif args.bb_command == 'list-programs':
        programs = manager.list_programs()
        if programs:
            print("Programas de Bug Bounty:")
            for program in programs:
                print(f"  - {program}")
        else:
            print("No hay programas configurados")
        
    elif args.bb_command == 'list-findings':
        findings = manager.list_findings(args.program) if args.program else manager.list_all_findings()
        if findings:
            print(f"Hallazgos {'para ' + args.program if args.program else ''}:")
            for finding in findings:
                severity = finding.get('severity', 'unknown').upper()
                print(f"  [{severity}] {finding.get('id', 'unknown')}: {finding.get('title', 'Sin título')}")
        else:
            print(f"No hay hallazgos {'para ' + args.program if args.program else ''}")
        
    elif args.bb_command == 'generate-report':
        report = manager.generate_report(args.finding_id, format=args.format)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"[+] Reporte guardado en {args.output}")
        else:
            print(report)
        
    elif args.bb_command == 'submit':
        # Get finding
        finding = manager.get_finding(args.finding_id)
        if not finding:
            print(f"[-] Hallazgo '{args.finding_id}' no encontrado")
            return
        
        # Submit based on platform
        if args.platform == 'hackerone':
            integration = HackerOneIntegration(args.api_token)
            result = integration.submit_report(args.program_handle, finding)
        elif args.platform == 'bugcrowd':
            integration = BugcrowdIntegration(args.api_token)
            result = integration.submit_report(args.program_handle, finding)
        else:
            print(f"[-] Plataforma '{args.platform}' no soportada")
            return
        
        if args.dry_run:
            print(f"[!] DRY RUN: Reporte que se enviaría:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"[+] Reporte enviado a {args.platform}")
            print(f"    ID: {result.get('id', 'unknown')}")
            print(f"    Estado: {result.get('state', 'unknown')}")


def _handle_auth(args):
    """Handle auth commands."""
    from pentesting.auth import get_auth_manager
    import json
    
    auth_manager = get_auth_manager()
    
    if args.auth_command == 'add-session':
        # Parse cookies
        cookies = {}
        if args.cookies:
            for cookie in args.cookies.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key.strip()] = value.strip()
        
        # Parse headers
        headers = {}
        if args.headers:
            try:
                headers = json.loads(args.headers)
            except json.JSONDecodeError:
                print("[-] Headers inválidos (debe ser JSON)")
                return
        
        # Add session
        auth_manager.add_session(
            name=args.name,
            cookies=cookies,
            headers=headers,
            token=args.token,
            username=args.username,
            password=args.password,
            base_url=args.base_url,
            auth_type=args.auth_type
        )
        print(f"[+] Sesión '{args.name}' agregada")
        
    elif args.auth_command == 'list-sessions':
        sessions = auth_manager.list_sessions()
        if sessions:
            print("Sesiones guardadas:")
            for session in sessions:
                print(f"  - {session}")
        else:
            print("No hay sesiones guardadas")
        
    elif args.auth_command == 'remove-session':
        if auth_manager.remove_session(args.name):
            print(f"[+] Sesión '{args.name}' eliminada")
        else:
            print(f"[-] Sesión '{args.name}' no encontrada")
        
    elif args.auth_command == 'oauth2-token':
        try:
            token_data = auth_manager.oauth2_token(
                token_url=args.token_url,
                client_id=args.client_id,
                client_secret=args.client_secret,
                scope=args.scope or '',
                grant_type=args.grant_type
            )
            print("[+] Token OAuth2 obtenido:")
            print(f"    Access Token: {token_data.get('access_token', 'N/A')[:20]}...")
            print(f"    Token Type: {token_data.get('token_type', 'N/A')}")
            print(f"    Expires In: {token_data.get('expires_in', 'N/A')} segundos")
        except Exception as e:
            print(f"[-] Error obteniendo token: {e}")


def _handle_report(args):
    """Handle report generation command."""
    from reporting.advanced import ProfessionalReporter
    import json
    
    # Load input
    with open(args.input, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Create reporter
    reporter = ProfessionalReporter()
    
    # Generate report
    if args.format == 'json':
        # Just reformat
        output_path = args.output
        if output_path.is_dir():
            output_path = output_path / 'report.json'
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        report = reporter.generate_report(data, format=args.format)
        
        # Save report
        if args.output.is_dir():
            extension = 'html' if args.format == 'html' else 'md'
            output_path = args.output / f'report.{extension}'
        else:
            output_path = args.output
        
        with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(report)
    
    print(f"[+] Reporte generado en {output_path}")


def _handle_poc(args):
    """Handle PoC generation command."""
    import json
    
    # Load input
    with open(args.input, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Find the specific finding
    finding = None
    for f in data.get('findings', []):
        if f.get('id') == args.finding_id:
            finding = f
            break
    
    if not finding:
        print(f"[-] Hallazgo '{args.finding_id}' no encontrado")
        return
    
    # Determine output path
    if args.output:
        output_path = args.output
    else:
        # Create a safe filename
        target = finding.get('target', 'unknown')
        vuln_type = finding.get('type', finding.get('vulnerability_type', 'unknown'))
        safe_target = target.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
        output_path = Path(f'poc_{safe_target}_{args.finding_id}.{args.language}')
    
    # Generate PoC
    _generate_poc(finding, output_path, language=args.language, target_override=args.target)
    print(f"[+] PoC generado en {output_path}")


def _generate_poc(finding, output_path, language='python', target_override=None):
    """Generate a Proof of Concept for a finding."""
    target = target_override or finding.get('target', 'http://example.com')
    vuln_type = finding.get('type', finding.get('vulnerability_type', 'unknown'))
    parameter = finding.get('parameter', finding.get('location', {}).get('parameter', ''))
    payload = finding.get('payload', finding.get('evidence', {}).get('payload', ''))
    method = finding.get('method', 'GET').upper()
    
    if language == 'python':
        poc = f'''#!/usr/bin/env python3
"""
Proof of Concept for {vuln_type.upper()} vulnerability
Target: {target}
Parameter: {parameter}
Payload: {payload}
"""

import requests
import sys

def exploit():
    url = "{target}"
    
    # Vulnerable parameter
    param = "{parameter}"
    payload = "{payload}"
    
    # Build request
    params = {{param: payload}} if param else {{}}
    
    # For POST requests
    data = {{param: payload}} if param else {{}}
    
    print(f"[*] Testing {vuln_type.upper()} on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print(f"[*] Payload: {{payload}}")
    
    try:
        if "{method}" == "GET":
            response = requests.get(url, params=params, timeout=10)
        elif "{method}" == "POST":
            response = requests.post(url, data=data, timeout=10)
        else:
            response = requests.request("{method}", url, data=data, params=params, timeout=10)
        
        print(f"[+] Status Code: {{response.status_code}}")
        print(f"[+] Response Length: {{len(response.text)}} bytes")
        
        # Check for evidence
        if "{payload}" in response.text:
            print("[+] Payload reflected in response!")
        
        # For SQLi, check for errors
        error_patterns = ['sql syntax', 'mysql', 'postgresql', 'oracle', 'syntax error']
        if any(pattern in response.text.lower() for pattern in error_patterns):
            print("[+] SQL error detected!")
        
        # Save response
        with open("response.html", "w") as f:
            f.write(response.text)
        print("[+] Response saved to response.html")
        
    except Exception as e:
        print(f"[-] Error: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()
'''
    
    elif language == 'bash':
        poc = f'''#!/bin/bash
# Proof of Concept for {vuln_type.upper()} vulnerability
# Target: {target}
# Parameter: {parameter}
# Payload: {payload}

URL="{target}"
PARAM="{parameter}"
PAYLOAD="{payload}"

# URL encode the payload
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('{payload}'))" 2>/dev/null || echo "{payload}")

echo "[*] Testing {vuln_type.upper()} on $URL"
echo "[*] Parameter: $PARAM"
echo "[*] Payload: $PAYLOAD"

if [ "{method}" = "GET" ]; then
    if [ -n "$PARAM" ]; then
        curl -v "$URL?$PARAM=$ENCODED_PAYLOAD" 2>&1 | tee response.txt
    else
        curl -v "$URL" 2>&1 | tee response.txt
    fi
elif [ "{method}" = "POST" ]; then
    if [ -n "$PARAM" ]; then
        curl -v -X POST -d "$PARAM=$ENCODED_PAYLOAD" "$URL" 2>&1 | tee response.txt
    else
        curl -v -X POST "$URL" 2>&1 | tee response.txt
    fi
else
    curl -v -X {method} -d "$PARAM=$ENCODED_PAYLOAD" "$URL" 2>&1 | tee response.txt
fi

echo ""
echo "[+] Response saved to response.txt"

# Check for evidence
if grep -q "$PAYLOAD" response.txt; then
    echo "[+] Payload reflected in response!"
fi

# Check for SQL errors
if grep -qi "sql syntax\|mysql\|postgresql\|oracle\|syntax error" response.txt; then
    echo "[+] SQL error detected!"
fi
'''
    
    elif language == 'curl':
        poc = f'''#!/bin/bash
# Proof of Concept using curl for {vuln_type.upper()}
# Target: {target}
# Parameter: {parameter}
# Payload: {payload}

# URL encode the payload
ENCODED_PAYLOAD="{payload}"

# For GET requests
if [ "{method}" = "GET" ]; then
    if [ -n "{parameter}" ]; then
        curl -v "{target}?{parameter}=$ENCODED_PAYLOAD"
    else
        curl -v "{target}"
    fi
# For POST requests
elif [ "{method}" = "POST" ]; then
    if [ -n "{parameter}" ]; then
        curl -v -X POST -d "{parameter}=$ENCODED_PAYLOAD" "{target}"
    else
        curl -v -X POST "{target}"
    fi
# For other methods
else
    curl -v -X {method} -d "{parameter}=$ENCODED_PAYLOAD" "{target}"
fi
'''
    else:
        poc = f"# Unsupported language: {language}"
    
    # Write PoC to file
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(poc)
    
    # Make executable if bash
    if language in ['bash', 'curl']:
        try:
            output_path.chmod(0o755)
        except (OSError, AttributeError):
            pass


# Import required for backward compatibility
import os


if __name__ == '__main__':
    raise SystemExit(main())
