"""
Native PHP Analyzer para Security Advisor Auditor v2.2
Mejora 5: analizador PHP offline basado en el motor de reglas compartido
(regex_rules.RuleEngine), sin dependencias externas (no requiere PHP ni
PHPStan). PHPAnalyzer hereda de JavaScriptAnalyzer reutilizando la
infraestructura; el motor se configura con reglas PHP.
"""

from pathlib import Path
from typing import List, Optional, Union

from .base_analyzer import Finding, ScanResult
from .js_analyzer import JavaScriptAnalyzer
from .regex_rules import Rule

# Reglas para PHP (offline)
PHP_RULES: List[Rule] = [
    Rule(
        rule_id="PHP001",
        title="Uso de eval()",
        category="rce",
        severity="critical",
        confidence="high",
        pattern=r"\beval\s*\(",
        message="eval() ejecuta codigo arbitrario; con entrada controlable provoca RCE",
        remediation="Eliminar eval(); usar estructuras de datos y funciones explicitas",
        tags=["owasp:a03"],
    ),
    Rule(
        rule_id="PHP002",
        title="Ejecucion de comandos del sistema",
        category="command_injection",
        severity="critical",
        confidence="medium",
        pattern=r"\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(",
        message="Funcion de ejecucion de comandos; con entrada controlable hay inyeccion de comandos",
        remediation="Usar escapeshellarg/escapeshellcmd o evitar llamadas al sistema",
        tags=["owasp:a03"],
    ),
    Rule(
        rule_id="PHP003",
        title="Consulta mysql_* (API obsoleta, posible SQLi)",
        category="sqli",
        severity="high",
        confidence="medium",
        pattern=r"\bmysql_(query|fetch_array|fetch_assoc|connect|select_db|real_escape_string)\s*\(",
        message="La extension mysql_* esta obsoleta y no soporta consultas preparadas",
        remediation="Migrar a PDO o mysqli con consultas preparadas (prepared statements)",
        tags=["owasp:a03"],
    ),
    Rule(
        rule_id="PHP004",
        title="Eco directo de datos externas (XSS)",
        category="xss",
        severity="high",
        confidence="medium",
        pattern=r"(echo|print)(?![^;]*htmlspecialchars)[^;]*\$_(GET|POST|REQUEST|COOKIE)",
        message="Los datos de superglobales se envian al navegador sin escapar",
        remediation="Escapar con htmlspecialchars() antes de imprimir datos externas",
        tags=["owasp:a03"],
    ),
    Rule(
        rule_id="PHP005",
        title="Include/require con datos externas (LFI/RFI)",
        category="file_inclusion",
        severity="critical",
        confidence="high",
        pattern=r"(include|require)(_once)?\s*\(?\s*[^;]*\$_(GET|POST|REQUEST)",
        message="Inclusion de ficheros con ruta controlable permite LFI/RFI",
        remediation="Usar una lista blanca de rutas permitidas; nunca componer rutas con datos externas",
        tags=["owasp:a01"],
    ),
    Rule(
        rule_id="PHP006",
        title="Secreto/credencial hardcodeado",
        category="hardcoded_secret",
        severity="high",
        confidence="medium",
        pattern=r"(api[_-]?key|secret|password|passwd|token|db_pass)[\"']?\s*[=:]\s*[\"'][^\"']{8,}[\"']",
        message="Posible credencial escrita en el codigo",
        remediation="Mover el secreto a variables de entorno y rotarlo",
        tags=["secrets"],
        case_insensitive=True,
    ),
    Rule(
        rule_id="PHP007",
        title="unserialize() con datos externas",
        category="deserialization",
        severity="critical",
        confidence="medium",
        pattern=r"unserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
        message="Deserializar datos controlables permite ataques de deserializacion (POP)",
        remediation="Usar json_decode o validar el esquema antes de deserializar",
        tags=["owasp:a08"],
    ),
    Rule(
        rule_id="PHP008",
        title="Redireccion con datos externas (open redirect)",
        category="open_redirect",
        severity="medium",
        confidence="medium",
        pattern=r"header\s*\(\s*['\"]Location:[^)]*\$_(GET|POST|REQUEST)",
        message="Redireccion con destino controlable permite open redirect y phishing",
        remediation="Validar el destino contra una lista blanca antes de redirigir",
        tags=["owasp:a01"],
    ),
]


class PHPAnalyzer(JavaScriptAnalyzer):
    """
    Analizador nativo PHP: offline y sin dependencias.
    Reutiliza la infraestructura de JavaScriptAnalyzer con reglas PHP.
    """

    TOOL_NAME = "php_native"
    SUPPORTED_LANGUAGES = ["php", "php3", "php4", "php5", "php7", "php8"]
    LANGUAGE = "php"

    @classmethod
    def default_rules(cls) -> List[Rule]:
        return list(PHP_RULES)

    def analyze_directory(self, dir_path: Union[str, Path], languages: Optional[List[str]] = None) -> ScanResult:
        root = Path(dir_path)
        if not root.exists():
            return ScanResult(target=str(root), tool=self.TOOL_NAME, language=self.LANGUAGE, findings=[], errors=["Directorio no encontrado: " + str(root)], success=False)
        all_findings: List[Finding] = []
        errors: List[str] = []
        for path in sorted(root.rglob("*")):
            if path.suffix in (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8"):
                try:
                    all_findings.extend(self.engine.scan_file(str(path)))
                except OSError as exc:
                    errors.append("Error leyendo " + str(path) + ": " + str(exc))
        return ScanResult(
            target=str(root),
            tool=self.TOOL_NAME,
            language=self.LANGUAGE,
            findings=all_findings,
            statistics={"files_scanned": len(all_findings), "by_severity": self._count_by_severity(all_findings)},
            errors=errors,
            success=True,
        )
