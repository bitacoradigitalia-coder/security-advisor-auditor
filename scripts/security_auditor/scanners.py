"""Dependency discovery only: never install, run scanners, or send private code."""
import shutil

TOOL_PURPOSES = {
    'git': 'Identificación de commit (rev-parse local, si disponible)',
    'rg': 'Búsqueda dirigida para revisión del agente',
    'semgrep': 'Análisis estático con reglas locales revisadas',
    'gitleaks': 'Detección ampliada de secretos; redactar salida',
    'osv-scanner': 'Advisories de dependencias; requiere política de red explícita',
    'trivy': 'Dependencias/IaC; bases locales y política de red explícita',
}


def capabilities():
    result = [{'name': 'python-ast', 'status': 'available_not_executed',
               'purpose': 'Análisis sintáctico sin importar ni ejecutar el objetivo'}]
    for name, purpose in TOOL_PURPOSES.items():
        result.append({'name': name, 'status': 'available_not_executed' if shutil.which(name)
                       else 'unavailable', 'purpose': purpose})
    return result


def plans():
    """Plans need version/flag validation before use; never passed to a shell here."""
    return {'tools': capabilities(), 'execution': 'not_executed',
            'requirements': ['Autorización antes de instalar o descargar',
                             'Verificar versión y flags en documentación oficial',
                             'Reglas/configuración confiables; nunca auto-config del objetivo',
                             'Redacción antes de incorporar resultados',
                             'No escaneo activo de servicios públicos',
                             'Datos privados y consultas externas requieren consentimiento'],
            'documentation': {
                'semgrep': 'https://semgrep.dev/docs/cli-reference',
                'gitleaks': 'https://github.com/gitleaks/gitleaks',
                'osv-scanner': 'https://google.github.io/osv-scanner/',
                'trivy': 'https://trivy.dev/latest/docs/'}}
