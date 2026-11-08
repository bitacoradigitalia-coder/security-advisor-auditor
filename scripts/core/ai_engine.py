"""
AI Engine for Security Advisor Auditor v2.2
FASE 5 (IA): interpretacion contextual y priorizacion automatica de hallazgos.

"IA" aqui significa un motor heuristico determinista y offline (sin modelos
externos, sin llamadas a APIs): interpreta el contexto de cada hallazgo
(evidencias, estado de verificacion, explotabilidad, correlaciones entre
hallazgos del mismo tipo/objetivo, contexto del endpoint) y calcula una
puntuacion de riesgo que ordena automaticamente la cola de trabajo del auditor.

Mejora 6: deduplicacion automatica de hallazgos identicos (mismo nombre,
tipo, objetivo, endpoint, parametro, payload y estado de verificacion) y
ponderacion por contexto del endpoint (bono en endpoints de autenticacion
o administracion).

Integra con los Engines de FASE 2: consume Findings de EvidenceEngine y
respeta los estados de VerificationEngine.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .evidence_engine import ConfidenceLevel, Finding, VerificationStatus

# Endpoints cuyo contexto eleva el riesgo (autenticacion / administracion)
SENSITIVE_ENDPOINT_MARKERS: Tuple[str, ...] = (
    "/login",
    "/signin",
    "/auth",
    "/admin",
    "/session",
    "/password",
    "/token",
    "/upload",
    "/api/auth",
)


class PriorityLevel(Enum):
    """Niveles de prioridad de remediacion."""
    P0 = "P0"  # Critico: explotar/remediar inmediatamente
    P1 = "P1"  # Alto: remediar esta iteracion
    P2 = "P2"  # Medio: planificar
    P3 = "P3"  # Bajo: backlog
    P4 = "P4"  # Informativo / falso positivo


@dataclass
class PriorityAssessment:
    """Evaluacion de prioridad de un hallazgo."""
    finding_id: str
    risk_score: float = 0.0          # 0-100
    priority: PriorityLevel = PriorityLevel.P4
    rationale: List[str] = field(default_factory=list)
    context_signals: Dict[str, Any] = field(default_factory=dict)
    correlated_with: List[str] = field(default_factory=list)
    recommended_action: str = ""
    duplicates_merged: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "risk_score": round(self.risk_score, 1),
            "priority": self.priority.value,
            "rationale": self.rationale,
            "context_signals": self.context_signals,
            "correlated_with": self.correlated_with,
            "recommended_action": self.recommended_action,
            "duplicates_merged": self.duplicates_merged,
        }


class AIEngine:
    """
    Motor de interpretacion contextual y priorizacion automatica.

    Metodologia (determinista y auditable):
    1. Interpretar el contexto: evidencias, verificacion, explotabilidad,
       correlacion con otros hallazgos del mismo tipo y objetivo y contexto
       del endpoint (autenticacion/administracion eleva el riesgo).
    2. Calcular riesgo: severidad base ponderada por confianza, estado de
       verificacion y bonos de evidencia/explotabilidad/correlacion/endpoint.
    3. Emitir una evaluacion con justificacion (rationale) accionable.
    """

    TOOL_NAME = "ai_engine"

    SEVERITY_WEIGHT = {"critical": 45.0, "high": 35.0, "medium": 20.0, "low": 10.0, "info": 5.0}
    CONFIDENCE_MULT = {
        ConfidenceLevel.CONFIRMED: 1.3,
        ConfidenceLevel.HIGH: 1.2,
        ConfidenceLevel.MEDIUM: 1.0,
        ConfidenceLevel.LOW: 0.7,
        ConfidenceLevel.FALSE: 0.0,
    }
    VERIFICATION_MULT = {
        VerificationStatus.CONFIRMED: 1.25,
        VerificationStatus.PROBABLE: 1.10,
        VerificationStatus.CANDIDATE: 1.00,
        VerificationStatus.NOT_VERIFIED: 0.90,
        VerificationStatus.FALSE_POSITIVE: 0.0,
    }
    PRIORITY_BANDS = [(75.0, PriorityLevel.P0), (55.0, PriorityLevel.P1), (35.0, PriorityLevel.P2), (20.0, PriorityLevel.P3)]
    SENSITIVE_ENDPOINT_BONUS = 10.0

    def __init__(self, evidence_engine: Optional[Any] = None) -> None:
        self.evidence_engine = evidence_engine

    # ------------------------------------------------------------------
    # Deduplicacion (mejora 6)
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup_key(finding: Finding) -> Tuple[str, str, str, str, str, str, str]:
        """Clave conservadora de deduplicacion.

        Incluye nombre y estado de verificacion para NO fusionar jamas un
        hallazgo vivo con un falso positivo ni hallazgos con distinta
        descripcion (misma categoria en el mismo sitio puede ser legitimo).
        """
        return (
            str(finding.name or ""),
            str(finding.vulnerability_type or ""),
            str(finding.target or ""),
            str(getattr(finding, "endpoint", "") or ""),
            str(getattr(finding, "parameter", "") or ""),
            str(getattr(finding, "payload", "") or ""),
            finding.verification_status.value,
        )

    def deduplicate_findings(self, findings: List[Finding]) -> Tuple[List[Finding], Dict[str, List[str]]]:
        """Fusionar hallazgos identicos segun _dedup_key.

        Devuelve (hallazgos unicos, mapa id_canonico -> [ids_fusionados]).
        Se conserva la primera aparicion; los duplicados quedan registrados.
        """
        kept: List[Finding] = []
        duplicates: Dict[str, List[str]] = {}
        seen: Dict[Tuple[str, str, str, str, str, str, str], str] = {}
        for finding in findings:
            key = self._dedup_key(finding)
            if key in seen:
                duplicates.setdefault(seen[key], []).append(finding.finding_id)
                continue
            seen[key] = finding.finding_id
            kept.append(finding)
            duplicates[finding.finding_id] = []
        return kept, duplicates

    # ------------------------------------------------------------------
    # Interpretacion contextual
    # ------------------------------------------------------------------

    def interpret_context(self, finding: Finding, all_findings: Optional[List[Finding]] = None) -> Dict[str, Any]:
        """Extraer las senales de contexto de un hallazgo."""
        signals: Dict[str, Any] = {}
        signals["severity"] = finding.severity
        signals["confidence"] = finding.confidence.value
        signals["verification_status"] = finding.verification_status.value
        signals["evidence_count"] = len(finding.evidences)
        signals["has_reproduction_steps"] = bool(finding.reproduction_steps)
        signals["has_payload"] = bool(finding.payload)
        signals["has_cvss"] = finding.cvss is not None
        signals["vulnerability_type"] = finding.vulnerability_type or "unknown"
        if finding.cvss is not None:
            signals["cvss"] = finding.cvss
        # Contexto del endpoint (mejora 6)
        endpoint_context = (str(getattr(finding, "endpoint", "") or "") + " " + str(finding.target or "")).lower()
        sensitive_hits = [m for m in SENSITIVE_ENDPOINT_MARKERS if m in endpoint_context]
        if sensitive_hits:
            signals["sensitive_endpoint"] = sensitive_hits[0]
        # Correlacion: mismo tipo de vulnerabilidad en el mismo objetivo
        correlated: List[str] = []
        if all_findings:
            for other in all_findings:
                if other is finding or other.finding_id == finding.finding_id:
                    continue
                if other.vulnerability_type and other.vulnerability_type == finding.vulnerability_type and other.target == finding.target:
                    correlated.append(other.finding_id)
        signals["correlated_count"] = len(correlated)
        return signals

    # ------------------------------------------------------------------
    # Priorizacion automatica
    # ------------------------------------------------------------------

    def prioritize_finding(self, finding: Finding, all_findings: Optional[List[Finding]] = None) -> PriorityAssessment:
        """Calcular la prioridad de un hallazgo con su justificacion."""
        signals = self.interpret_context(finding, all_findings)
        rationale: List[str] = []

        if finding.verification_status == VerificationStatus.FALSE_POSITIVE or finding.confidence == ConfidenceLevel.FALSE:
            return PriorityAssessment(
                finding_id=finding.finding_id,
                risk_score=0.0,
                priority=PriorityLevel.P4,
                rationale=["Descartado: marcado como falso positivo por el VerificationEngine"],
                context_signals=signals,
                recommended_action="Cerrar el hallazgo (falso positivo) y registrar la justificacion",
            )

        base = self.SEVERITY_WEIGHT.get(finding.severity, 10.0)
        rationale.append("Severidad '" + finding.severity + "' -> base " + str(base))

        conf_mult = self.CONFIDENCE_MULT.get(finding.confidence, 0.7)
        rationale.append("Confianza " + finding.confidence.value + " -> x" + str(conf_mult))

        ver_mult = self.VERIFICATION_MULT.get(finding.verification_status, 0.9)
        rationale.append("Verificacion " + finding.verification_status.value + " -> x" + str(ver_mult))

        score = base * conf_mult * ver_mult

        evidence_bonus = min(signals.get("evidence_count", 0) * 2.0, 10.0)
        if evidence_bonus:
            score += evidence_bonus
            rationale.append("Evidencias: " + str(signals.get("evidence_count", 0)) + " -> +" + str(evidence_bonus))

        if signals.get("has_reproduction_steps"):
            score += 5.0
            rationale.append("Tiene pasos de reproduccion -> +5")
        if signals.get("has_payload"):
            score += 3.0
            rationale.append("Tiene payload explotable registrado -> +3")

        # Bono por contexto del endpoint (mejora 6)
        if signals.get("sensitive_endpoint"):
            score += self.SENSITIVE_ENDPOINT_BONUS
            rationale.append("Endpoint sensible '" + str(signals["sensitive_endpoint"]) + "' -> +" + str(self.SENSITIVE_ENDPOINT_BONUS))

        correlated_ids: List[str] = []
        if all_findings:
            for other in all_findings:
                if other is finding or other.finding_id == finding.finding_id:
                    continue
                if other.vulnerability_type and other.vulnerability_type == finding.vulnerability_type and other.target == finding.target:
                    correlated_ids.append(other.finding_id)
        if correlated_ids:
            corr_bonus = min(len(correlated_ids) * 2.0, 6.0)
            score += corr_bonus
            rationale.append("Correlacionado con " + str(len(correlated_ids)) + " hallazgo(s) del mismo tipo/objetivo -> +" + str(corr_bonus))

        score = max(0.0, min(score, 100.0))

        priority = PriorityLevel.P4
        for threshold, level in self.PRIORITY_BANDS:
            if score >= threshold:
                priority = level
                break

        return PriorityAssessment(
            finding_id=finding.finding_id,
            risk_score=score,
            priority=priority,
            rationale=rationale,
            context_signals=signals,
            correlated_with=correlated_ids,
            recommended_action=self._recommend(priority, finding),
        )

    def prioritize_findings(self, findings: List[Finding], deduplicate: bool = True) -> List[PriorityAssessment]:
        """Priorizar todos los hallazgos y devolverlos ordenados por riesgo descendente.

        Con deduplicate=True (por defecto) fusiona primero los hallazgos
        identicos y registra los IDs duplicados en cada evaluacion.
        """
        if deduplicate:
            unique, duplicates = self.deduplicate_findings(findings)
        else:
            unique, duplicates = findings, {f.finding_id: [] for f in findings}
        assessments = [self.prioritize_finding(f, unique) for f in unique]
        for a in assessments:
            a.duplicates_merged = duplicates.get(a.finding_id, [])
        _rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
        assessments.sort(key=lambda a: (_rank.get(a.priority.value, 9), -a.risk_score))
        return assessments

    def get_top(self, findings: List[Finding], n: int = 5, deduplicate: bool = True) -> List[PriorityAssessment]:
        """Obtener los N hallazgos mas urgentes."""
        return self.prioritize_findings(findings, deduplicate=deduplicate)[: max(0, n)]

    def summary_report(self, findings: List[Finding], deduplicate: bool = True) -> Dict[str, Any]:
        """Informe resumen de priorizacion para el auditor."""
        assessments = self.prioritize_findings(findings, deduplicate=deduplicate)
        by_priority: Dict[str, int] = {}
        for a in assessments:
            by_priority[a.priority.value] = by_priority.get(a.priority.value, 0) + 1
        duplicates_removed = len(findings) - len(assessments)
        return {
            "total": len(findings),
            "unique": len(assessments),
            "duplicates_removed": duplicates_removed,
            "by_priority": by_priority,
            "average_risk": round(sum(a.risk_score for a in assessments) / len(assessments), 1) if assessments else 0.0,
            "p0_ids": [a.finding_id for a in assessments if a.priority == PriorityLevel.P0],
            "false_positives": sum(1 for a in assessments if a.priority == PriorityLevel.P4),
        }

    def _recommend(self, priority: PriorityLevel, finding: Finding) -> str:
        """Siguiente accion recomendada segun prioridad."""
        if priority == PriorityLevel.P0:
            return "Remediar inmediatamente; explotacion confirmada o inminente en '" + finding.name + "'"
        if priority == PriorityLevel.P1:
            return "Programar remediacion en la iteracion actual; validar explotabilidad de '" + finding.name + "'"
        if priority == PriorityLevel.P2:
            return "Planificar remediacion; recopilar mas evidencias si la confianza es baja"
        if priority == PriorityLevel.P3:
            return "Aniadir al backlog de endurecimiento"
        return "Revisar si procede cerrarlo como informativo"
