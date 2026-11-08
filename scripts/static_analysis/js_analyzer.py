"""
Native JavaScript Analyzer para Security Advisor Auditor v2.2
FASE 4 (Multilenguaje): analizador JavaScript offline, sin dependencias
externas (no requiere Node.js ni ESLint). Basado en el motor de reglas
compartido (regex_rules.RuleEngine).
"""

from pathlib import Path
from typing import Dict, List, Optional, Union

from .base_analyzer import BaseAnalyzer, Finding, ScanResult
from .regex_rules import Rule, RuleEngine

# Reglas para JavaScript (aplicables tambien a TypeScript salvo las marcadas)
JS_RULES: List[Rule] = [
    Rule(
        rule_id="JS001",
        title="Uso de eval()",
        category="rce",
        severity="critical",
        confidence="high",
        pattern=r"\beval\s*\(",
        message="eval() ejecuta codigo arbitrario; si la entrada es controlable provoca RCE",
        remediation="Eliminar eval(); usar JSON.parse para datos o funciones explicitas",
        references=["https://developer.mozilla.org/es/docs/Web/JavaScript/Reference/Global_Objects/eval"],
        tags=["owasp:a03"],
    ),
    Rule(
        rule_id="JS002",
        title="Constructor Function() con datos dinamicos",
        category="rce",
        severity="critical",
        confidence="medium",
        pattern=r"new\s+Function\s*\(",
        message="new Function() equivale a eval y ejecuta codigo generado dinamicamente",
        remediation="Evitar new Function(); usar funciones estaticas",
        tags=["owasp:a03"],
    ),
    Rule(
        rule_id="JS003",
        title="Escritura en el DOM con document.write",
        category="xss",
        severity="high",
        confidence="high",
        pattern=r"document\.write(ln)?\s*\(",
        message="document.write con datos no saneados provoca XSS",
        remediation="Usar textContent o createElement en lugar de document.write",
        tags=["owasp:a03", "dom"],
    ),
    Rule(
        rule_id="JS004",
        title="Asignacion a innerHTML",
        category="xss",
        severity="high",
        confidence="medium",
        pattern=r"\.(innerHTML|outerHTML|insertAdjacentHTML)\s*[=(]",
        message="Sink DOM vulnerable a XSS si se asigna contenido no saneado",
        remediation="Usar textContent o sanitizar con DOMPurify",
        tags=["owasp:a03", "dom"],
    ),
    Rule(
        rule_id="JS005",
        title="Sink React dangerouslySetInnerHTML",
        category="xss",
        severity="high",
        confidence="medium",
        pattern=r"dangerouslySetInnerHTML",
        message="Inserta HTML sin sanitizar en React",
        remediation="Sanitizar el HTML o renderizar texto",
        tags=["owasp:a03", "react"],
    ),
    Rule(
        rule_id="JS006",
        title="Posible inyeccion SQL por concatenacion",
        category="sqli",
        severity="critical",
        confidence="medium",
        pattern=r"(SELECT|INSERT|UPDATE|DELETE)[^\x22\x27]*[\x22\x27]?\s*\+|\+\s*[\x22\x27]\s*(SELECT|INSERT|UPDATE|DELETE)",
        message="Consulta SQL construida por concatenacion de strings",
        remediation="Usar consultas preparadas (prepared statements) y placeholders",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
        tags=["owasp:a03"],
        case_insensitive=True,
    ),
    Rule(
        rule_id="JS007",
        title="Ejecucion de comandos con child_process",
        category="command_injection",
        severity="critical",
        confidence="medium",
        pattern=r"child_process|\.(exec|execSync|execFile|spawn)\s*\(",
        message="Ejecucion de procesos hijos; si el comando incluye datos controlables hay inyeccion de comandos",
        remediation="Usar execFile con array de argumentos y validar la entrada",
        tags=["owasp:a03", "nodejs"],
    ),
    Rule(
        rule_id="JS008",
        title="Secreto/credencial hardcodeado",
        category="hardcoded_secret",
        severity="high",
        confidence="medium",
        pattern=r"(api[_-]?key|secret|password|passwd|token|access[_-]?key)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']",
        message="Posible credencial escrita en el codigo",
        remediation="Mover el secreto a variables de entorno y rotarlo",
        tags=["secrets"],
        case_insensitive=True,
    ),
    Rule(
        rule_id="JS009",
        title="Uso de protocolo HTTP sin TLS",
        category="transport_security",
        severity="medium",
        confidence="high",
        pattern=r"http://(?!localhost|127\.0\.0\.1|www\.w3\.org|schema\.w3\.org|www\.openid\.net|schemas\.xmlsoap\.org|purl\.org)",
        message="URL con HTTP sin cifrar",
        remediation="Usar HTTPS",
        tags=["owasp:a02"],
    ),
    Rule(
        rule_id="JS010",
        title="Contaminacion de prototipo (prototype pollution)",
        category="prototype_pollution",
        severity="high",
        confidence="medium",
        pattern=r"__proto__|\.prototype\[",
        message="Manipulacion de __proto__ o prototype; riesgo de prototype pollution",
        remediation="Validar claves y usar Object.create(null) o Map",
        tags=["nodejs"],
    ),
    Rule(
        rule_id="JS011",
        title="postMessage con origen comodin",
        category="postmessage",
        severity="medium",
        confidence="medium",
        pattern=r"postMessage\s*\([^)]*[\"']\*[\"']",
        message="postMessage con targetOrigin '*' expone datos a cualquier origen",
        remediation="Especificar el origen exacto en postMessage",
        tags=["dom"],
    ),
    Rule(
        rule_id="JS012",
        title="Almacenamiento de datos sensibles en localStorage",
        category="sensitive_storage",
        severity="medium",
        confidence="low",
        pattern=r"(localStorage|sessionStorage)\.setItem\s*\(\s*[\"'][^\"]*(token|jwt|password|secret)",
        message="Posible almacenamiento de tokens en almacenamiento web accesible por XSS",
        remediation="Usar cookies httpOnly o memoria",
        tags=["owasp:a07"],
        case_insensitive=True,
    ),
    Rule(
        rule_id="JS013",
        title="Math.random() para valores de seguridad",
        category="weak_random",
        severity="info",
        confidence="low",
        pattern=r"Math\.random\s*\(",
        message="Math.random() no es criptograficamente seguro",
        remediation="Usar crypto.getRandomValues() o crypto.randomBytes()",
        tags=["crypto"],
    ),
    Rule(
        rule_id="JS014",
        title="Serializacion insegura de datos no confiables",
        category="deserialization",
        severity="medium",
        confidence="low",
        pattern=r"(eval\s*\(|new\s+Function)[^\n]*JSON\.parse",
        message="Patron de deserializacion insegura combinando parse y ejecucion",
        remediation="Validar el esquema antes de procesar datos de terceros",
        tags=["owasp:a08"],
    ),
    Rule(
        rule_id="JS015",
        title="Uso de xml / parser XXE potencial",
        category="xxe",
        severity="medium",
        confidence="low",
        pattern=r"new\s+DOMParser\s*\(|xml2js|fast-xml-parser",
        message="Parseo de XML; verificar que las entidades externas estan deshabilitadas",
        remediation="Deshabilitar entidades externas (XXE)",
        tags=["owasp:a05"],
    ),
    Rule(
        rule_id="JS016",
        title="Posible redireccion abierta (open redirect)",
        category="open_redirect",
        severity="medium",
        confidence="medium",
        pattern=r"(location\.(href|replace|assign)|window\.open)\s*[\=(][^;]*(request|params|query|input|target|user)",
        message="Redireccion con destino derivado de datos externos permite open redirect y phishing",
        remediation="Validar el destino contra una lista blanca antes de redirigir",
        tags=["owasp:a01", "dom"],
    ),
    Rule(
        rule_id="JS017",
        title="setTimeout/setInterval con string de codigo",
        category="rce",
        severity="high",
        confidence="medium",
        pattern=r"set(Timeout|Interval)\(\s*[\x22\x27]",
        message="setTimeout con string equivale a eval y ejecuta codigo dinamicamente",
        remediation="Pasar una funcion en lugar de un string a setTimeout/setInterval",
        tags=["owasp:a03"],
    ),
]


class JavaScriptAnalyzer(BaseAnalyzer):
    """
    Analizador nativo JavaScript: offline y sin dependencias.
    Detecta patrones peligrosos comunes (XSS, RCE, SQLi, secretos, etc.)
    mediante el motor de reglas compartido.
    """

    TOOL_NAME = "js_native"
    SUPPORTED_LANGUAGES = ["javascript", "js", "jsx"]

    LANGUAGE = "javascript"

    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        super().__init__()
        self.engine = RuleEngine(self.TOOL_NAME, self.LANGUAGE, rules if rules is not None else self.default_rules())

    @classmethod
    def default_rules(cls) -> List[Rule]:
        return list(JS_RULES)

    def _validate_installation(self) -> None:
        # Analizador nativo: no requiere instalacion externa
        pass

    def is_available(self) -> bool:
        return True

    def analyze_code(self, code: str, language: str = "", file_path: str = "<stdin>") -> ScanResult:
        findings = self.engine.scan_code(code, file_path=file_path)
        return ScanResult(
            target=file_path,
            tool=self.TOOL_NAME,
            language=self.LANGUAGE,
            findings=findings,
            statistics={
                "rules": len(self.engine.rules),
                "lines": len(code.split("\n")),
                "by_severity": self._count_by_severity(findings),
                "by_category": self._count_by_category(findings),
            },
            errors=[],
            success=True,
        )

    def analyze_file(self, file_path: Union[str, Path], language: str = "") -> ScanResult:
        path = Path(file_path)
        if not path.exists():
            return ScanResult(target=str(path), tool=self.TOOL_NAME, language=self.LANGUAGE, findings=[], errors=["Archivo no encontrado: " + str(path)], success=False)
        findings = self.engine.scan_file(str(path))
        return ScanResult(
            target=str(path),
            tool=self.TOOL_NAME,
            language=self.LANGUAGE,
            findings=findings,
            statistics={"by_severity": self._count_by_severity(findings), "by_category": self._count_by_category(findings)},
            errors=[],
            success=True,
        )

    def analyze_directory(self, dir_path: Union[str, Path], languages: Optional[List[str]] = None) -> ScanResult:
        root = Path(dir_path)
        if not root.exists():
            return ScanResult(target=str(root), tool=self.TOOL_NAME, language=self.LANGUAGE, findings=[], errors=["Directorio no encontrado: " + str(root)], success=False)
        all_findings: List[Finding] = []
        errors: List[str] = []
        for path in sorted(root.rglob("*")):
            if path.suffix in (".js", ".jsx", ".mjs", ".cjs"):
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
