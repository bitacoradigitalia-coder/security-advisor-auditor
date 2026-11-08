"""
Tests del modulo SCA (mejora M12): SBOM CycloneDX, matching offline
determinista contra la cache de advisories y hallazgos con fix sugerido.
"""
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = str(Path(__file__).resolve().parents[1] / "scripts")
FIXTURES_DIR = str(Path(__file__).resolve().parent / "fixtures")
for p in (SCRIPTS_DIR, FIXTURES_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from core.evidence_engine import EvidenceEngine, VerificationStatus
from sca.osv_client import OSVClient, is_affected
from sca.sbom import SBOMGenerator, parse_requirements
from sca.scanner import SCAScanner

FIXTURE_REQ = str(Path(FIXTURES_DIR) / "sca" / "requirements.txt")


class TestSBOM(unittest.TestCase):
    def test_sbom_cyclonedx_valido(self):
        entries = parse_requirements(FIXTURE_REQ)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0], {"name": "requests", "spec": "==2.30.0"})

        sbom = SBOMGenerator().from_requirements(FIXTURE_REQ).to_dict()
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        names = [c["name"] for c in sbom["components"]]
        self.assertIn("requests", names)
        self.assertIn("pyyaml", names)
        req_component = next(c for c in sbom["components"] if c["name"] == "requests")
        self.assertEqual(req_component["version"], "2.30.0")

    def test_parse_requirements_ignora_comentarios(self):
        text_path = Path(FIXTURE_REQ)
        entries = parse_requirements(text_path)
        for entry in entries:
            self.assertNotIn("#", entry["spec"])


class TestOSVMatching(unittest.TestCase):
    def setUp(self):
        self.client = OSVClient(offline=True)

    def test_matching_offline_determinista(self):
        affected = self.client.check("requests", "2.30.0")
        self.assertEqual(len(affected), 1)
        self.assertEqual(affected[0].advisory_id, "GHSA-jpzg-p363-qq3p")
        # Determinista: misma llamada, mismo resultado
        self.assertEqual([a.advisory_id for a in self.client.check("requests", "2.30.0")],
                         [a.advisory_id for a in self.client.check("requests", "2.30.0")])

    def test_version_parcheada_no_afectada(self):
        self.assertEqual(self.client.check("requests", "2.31.0"), [])
        self.assertEqual(self.client.check("requests", "2.32.0"), [])

    def test_paquete_desconocido(self):
        self.assertEqual(self.client.check("inexistente-pkg", "1.0.0"), [])

    def test_is_affected_rangos(self):
        self.assertTrue(is_affected("2.30.0", "2.0.0", "2.31.0"))
        self.assertFalse(is_affected("1.9.9", "2.0.0", "2.31.0"))
        self.assertFalse(is_affected("2.31.0", "2.0.0", "2.31.0"))


class TestSCAScanner(unittest.TestCase):
    def test_hallazgo_con_fix_sugerido(self):
        engine = EvidenceEngine()
        scanner = SCAScanner(evidence_engine=engine)
        results = scanner.scan_requirements(parse_requirements(FIXTURE_REQ))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].package, "requests")

        findings = scanner.get_findings()
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, "vulnerable_dependency")
        self.assertEqual(finding.verification_status, VerificationStatus.CONFIRMED)
        self.assertIn("2.31.0", finding.description)  # fix sugerido
        self.assertTrue(finding.evidences)

    def test_requisitos_limpios_sin_hallazgos(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("pyyaml>=6.0\n")
            tmp = handle.name
        try:
            scanner = SCAScanner()
            results = scanner.scan_requirements(parse_requirements(tmp))
            self.assertEqual(results, [])
            self.assertEqual(scanner.get_findings(), [])
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
