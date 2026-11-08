"""
SCAScanner para Security Advisor Auditor v2.3 (mejora M12).

Recorre el SBOM (dependencias declaradas) y cruza cada paquete con los
advisories del OSVClient. Cada dependencia vulnerable genera un Finding
del EvidenceEngine con evidencia del advisory (severidad, CWE, fix
disponible). Offline por defecto.
"""
from typing import Any, Dict, List, Optional

# Import dual (preferir core.*; ver PLAN-v2.3 "Tecnicas validadas")
try:
    from core.evidence_engine import ConfidenceLevel, EvidenceEngine, EvidenceType, Finding, VerificationStatus
except ImportError:
    from scripts.core.evidence_engine import ConfidenceLevel, EvidenceEngine, EvidenceType, Finding, VerificationStatus  # type: ignore[no-redef]

try:
    from sca.osv_client import Advisory, OSVClient, lower_bound_version_of
except ImportError:
    from scripts.sca.osv_client import Advisory, OSVClient, lower_bound_version_of  # type: ignore[no-redef]


class SCAFinding:
    """Resultado SCA de una dependencia (independiente del EvidenceEngine)."""

    def __init__(self, package: str, version: str, advisory: Advisory) -> None:
        self.package = package
        self.version = version
        self.advisory = advisory

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "advisory": self.advisory.to_dict(),
        }


class SCAScanner:
    """Escaneo de composicion de software (SCA) offline sobre requirements.txt."""

    def __init__(
        self,
        osv_client: Optional[OSVClient] = None,
        evidence_engine: Optional[EvidenceEngine] = None,
    ) -> None:
        self.osv_client = osv_client or OSVClient(offline=True)
        self.evidence_engine = evidence_engine
        self._findings: List[Finding] = []

    def scan_requirements(self, entries: List[Dict[str, str]]) -> List[SCAFinding]:
        """entries: [{'name': ..., 'spec': ...}] (salida de parse_requirements)."""
        results: List[SCAFinding] = []
        for entry in entries:
            package = entry["name"]
            version = _version_of(entry["spec"])
            for advisory in self.osv_client.check(package, version):
                sca = SCAFinding(package, version, advisory)
                results.append(sca)
                self._create_finding(sca)
        return results

    def _create_finding(self, sca: SCAFinding) -> None:
        if self.evidence_engine is None:
            return
        advisory = sca.advisory
        finding = self.evidence_engine.create_finding(
            name="Dependencia vulnerable: " + sca.package + " " + sca.version,
            description=(
                advisory.summary + " Actualiza " + sca.package + " a " +
                advisory.fixed + " o superior. Advisory: " + advisory.advisory_id +
                " (" + advisory.url + ")."
            ),
            severity=advisory.severity,
            vulnerability_type="vulnerable_dependency",
            target=sca.package,
            endpoint=sca.package + "@" + sca.version,
            parameter="version",
            payload="",
            source="sca_scanner",
            tool="SCAScanner",
        )
        self.evidence_engine.add_evidence(
            finding_id=finding.finding_id,
            evidence_type=EvidenceType.LOG,
            response={"advisory": advisory.to_dict(), "installed": sca.version},
            parameter="version",
            verification_method="sca:version-match",
        )
        self.evidence_engine.set_verification_status(
            finding_id=finding.finding_id,
            status=VerificationStatus.CONFIRMED,
            confidence=ConfidenceLevel.CONFIRMED,
            verified_by="sca_scanner",
            notes="Version instalada " + sca.version + " en rango vulnerable [" +
                  advisory.introduced + ", " + advisory.fixed + ") del advisory " + advisory.advisory_id,
        )
        self._findings.append(finding)

    def get_findings(self) -> List[Finding]:
        return list(self._findings)


def _version_of(spec: str) -> str:
    return lower_bound_version_of(spec)
