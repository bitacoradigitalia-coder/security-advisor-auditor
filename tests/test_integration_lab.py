"""
Test de integracion del laboratorio vulnerable autorizado (mejora 3).

Arranca la app vulnerable en 127.0.0.1 (puerto efimero, hilo daemon) y
ejecuta el ActiveScanner real contra ella: descubrimiento de endpoints,
deteccion de vulnerabilidades y creacion de Findings con evidencia.
"""
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = str(Path(__file__).resolve().parents[1] / "scripts")
LAB_DIR = str(Path(__file__).resolve().parent / "lab")
for p in (SCRIPTS_DIR, LAB_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from core.evidence_engine import EvidenceEngine
from pentesting.scanner import ActiveScanner, ScanConfig
from vulnerable_app import VulnerableApp


class TestLaboratorioIntegracion(unittest.TestCase):
    """E2E: ActiveScanner contra la app vulnerable del laboratorio."""

    @classmethod
    def setUpClass(cls):
        cls.app = VulnerableApp()
        cls.base_url = cls.app.start()
        config = ScanConfig(
            target=cls.base_url,
            timeout=5,
            delay_between_requests=0.0,
            max_requests_per_second=1000,
        )
        cls.scanner = ActiveScanner(config=config, evidence_engine=EvidenceEngine())
        cls.results = cls.scanner.scan()

    @classmethod
    def tearDownClass(cls):
        cls.app.stop()

    def test_scan_sin_errores(self):
        self.assertNotIn("error", self.results)
        self.assertEqual(self.results["target"], self.base_url)
        self.assertGreater(self.results["statistics"]["requests_made"], 0)

    def test_descubre_endpoints_de_robots(self):
        endpoints = self.results["endpoints"]
        self.assertTrue(any("/private/" in e for e in endpoints))

    def test_detecta_cabeceras_y_cookies(self):
        vuln_types = {v["type"] for v in self.results["vulnerabilities"]}
        self.assertIn("missing_security_headers", vuln_types)
        self.assertIn("sensitive_cookies", vuln_types)

    def test_detecta_debug_expuesto(self):
        vuln_types = {v["type"] for v in self.results["vulnerabilities"]}
        self.assertIn("debug_information_exposed", vuln_types)

    def test_findings_con_evidencia(self):
        findings = self.scanner.get_findings()
        self.assertGreaterEqual(len(findings), 3)
        for finding in findings:
            self.assertTrue(finding.evidences)
            self.assertIn(finding.severity, ("low", "medium", "high", "critical"))

    def test_findings_aparecen_en_vulnerabilidades(self):
        vuln_types = {v["type"] for v in self.results["vulnerabilities"]}
        finding_types = {f.vulnerability_type for f in self.scanner.get_findings()}
        self.assertTrue(finding_types)
        self.assertTrue(finding_types.issubset(vuln_types))


if __name__ == "__main__":
    unittest.main()