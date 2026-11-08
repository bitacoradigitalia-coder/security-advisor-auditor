"""
Regex Rule Engine for Security Advisor Auditor v2.2
FASE 4 (Multilenguaje): motor de reglas compartido para analizadores nativos.

Arquitectura: cada regla es un objeto de datos (Rule); los analizadores
(JavaScript, TypeScript, y futuros lenguajes) definen listas de reglas y
delegan el escaneo en RuleEngine. Aniadir un lenguaje nuevo = escribir reglas.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base_analyzer import Finding


@dataclass
class Rule:
    """Una regla de deteccion basada en patron regex sobre lineas de codigo."""

    rule_id: str
    title: str
    category: str
    severity: str          # critical, high, medium, low, info
    confidence: str        # high, medium, low
    pattern: str           # expresion regular (se compila al registrar)
    message: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    case_insensitive: bool = False
    scan_comments: bool = False

    _compiled: Any = None

    def compile(self) -> "Rule":
        flags = re.IGNORECASE if self.case_insensitive else 0
        object.__setattr__(self, "_compiled", re.compile(self.pattern, flags))
        return self

    @property
    def regex(self) -> "re.Pattern[Any]":
        if self._compiled is None:
            self.compile()
        return self._compiled  # type: ignore[return-value]


class RuleEngine:
    """
    Escanea codigo linea a linea contra una lista de reglas.

    Genera objetos Finding normalizados del analizador base, con
    file/line/column/code para trazabilidad.
    """

    def __init__(self, tool_name: str, language: str, rules: List[Rule]) -> None:
        self.tool_name = tool_name
        self.language = language
        self.rules = [r.compile() for r in rules]

    def scan_code(self, code: str, file_path: str = "<stdin>", max_findings: Optional[int] = None) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.split("\n"), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            is_comment = stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")
            for rule in self.rules:
                if is_comment and not rule.scan_comments:
                    continue
                match = rule.regex.search(line)
                if not match:
                    continue
                finding = Finding(
                    id=rule.rule_id + ":" + file_path + ":" + str(lineno),
                    tool=self.tool_name,
                    language=self.language,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    type="vulnerability" if rule.severity in ("critical", "high") else "risk",
                    category=rule.category,
                    title=rule.title,
                    message=rule.message or rule.title,
                    description=(rule.message or rule.title) + ". Linea: " + str(lineno) + ".",
                    file=file_path,
                    line=lineno,
                    column=match.start() + 1,
                    code=line.strip()[:200],
                    evidence=line.strip()[:200],
                    remediation=rule.remediation,
                    fix=rule.remediation,
                    references=list(rule.references),
                    tags=[rule.rule_id] + list(rule.tags),
                )
                findings.append(finding)
                if max_findings is not None and len(findings) >= max_findings:
                    return findings
        return findings

    def scan_file(self, file_path: str) -> List[Finding]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
            return self.scan_code(handle.read(), file_path=file_path)

    def get_rule_ids(self) -> List[str]:
        return [r.rule_id for r in self.rules]
