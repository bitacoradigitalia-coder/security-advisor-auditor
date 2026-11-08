"""
Native TypeScript Analyzer para Security Advisor Auditor v2.2
FASE 4 (Multilenguaje): analizador TypeScript offline sin dependencias.

TypeScript es un superconjunto de JavaScript, por lo que hereda todas las
reglas JS del JavaScriptAnalyzer y aniade reglas especificas de TS que
anulan las garantias del sistema de tipos.
"""

from pathlib import Path
from typing import List, Optional, Union

from .base_analyzer import Finding, ScanResult
from .js_analyzer import JavaScriptAnalyzer
from .regex_rules import Rule, RuleEngine

# Reglas especificas de TypeScript
TS_RULES: List[Rule] = [
    Rule(
        rule_id="TS001",
        title="Cast 'as any' desactiva la comprobacion de tipos",
        category="unsafe_cast",
        severity="medium",
        confidence="medium",
        pattern=r"\bas\s+any\b",
        message="El cast 'as any' elimina las garantias del sistema de tipos en ese punto",
        remediation="Usar un tipo concreto o una type guard",
        tags=["typescript"],
    ),
    Rule(
        rule_id="TS002",
        title="Supresion de errores con @ts-ignore / @ts-expect-error",
        category="suppressed_error",
        severity="low",
        confidence="high",
        pattern=r"//\s*@(ts-ignore|ts-expect-error)",
        message="Suprimir errores del compilador puede ocultar vulnerabilidades o bugs",
        remediation="Corregir el error de tipo en lugar de ignorarlo",
        tags=["typescript"],
    ),
    Rule(
        rule_id="TS003",
        title="Asercion no-nula (!) sobre valor posiblemente indefinido",
        category="unsafe_cast",
        severity="low",
        confidence="low",
        pattern=r"[\w\)\]]+!\s*[.,;)]",
        message="Asercion de no-nulo: si el valor es undefined en ejecucion causara fallo o comportamiento inesperado",
        remediation="Comprobar el valor con una type guard o encadenado opcional (?.)",
        tags=["typescript"],
    ),
    Rule(
        rule_id="TS004",
        title="Asercion doble cast 'as 
unknown as'",
        category="unsafe_cast",
        severity="medium",
        confidence="medium",
        pattern=r"as\s+unknown\s+as",
        message="Doble cast: fuerza un tipo sin comprobacion alguna",
        remediation="Validar el dato en ejecucion antes de hacer el cast",
        tags=["typescript"],
    ),
]


class TypeScriptAnalyzer(JavaScriptAnalyzer):
    """
    Analizador nativo TypeScript: aplica las reglas JS heredadas
    (validas en TS salvo excepciones) mas las reglas especificas de TS.
    """

    TOOL_NAME = "ts_native"
    SUPPORTED_LANGUAGES = ["typescript", "ts", "tsx"]
    LANGUAGE = "typescript"

    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        # type: ignore[no-redef]
        JavaScriptAnalyzer.__init__(self, rules=rules if rules is not None else self.default_rules())
        # Sobreescribir el motor con lenguaje typescript
        self.engine = RuleEngine(self.TOOL_NAME, self.LANGUAGE, self.default_rules())

    @classmethod
    def default_rules(cls) -> List[Rule]:
        return list(JavaScriptAnalyzer.default_rules()) + list(TS_RULES)

    def analyze_directory(self, dir_path: Union[str, Path], languages: Optional[List[str]] = None) -> ScanResult:
        root = Path(dir_path)
        if not root.exists():
            return ScanResult(target=str(root), tool=self.TOOL_NAME, language=self.LANGUAGE, findings=[], errors=["Directorio no encontrado: " + str(root)], success=False)
        all_findings: List[Finding] = []
        errors: List[str] = []
        for path in sorted(root.rglob("*")):
            if path.suffix in (".ts", ".tsx"):
                try:
                    all_findings.extend(self.engine.scan_file(str(path)))
                except OSError as exc:
                    errors.append("Error leyendo " + str(path) + ": " + str(exc))
        return ScanResult(
            target=str(root),
            tool=self.TOOL_NAME,
            language=self.LANGUAGE,
            findings=all_finding
s,
            statistics={"by_severity": self._count_by_severity(all_findings)},
            errors=errors,
            success=True,
        )
