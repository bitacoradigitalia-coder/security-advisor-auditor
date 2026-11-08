"""
Tests del modulo OOB y del OOBScanner (mejora M11).

Cubre: registro y aislamiento de callbacks en OOBServer, OOBClient con
fetch inyectado, y E2E de SSRF ciego contra el laboratorio autorizado
(127.0.0.1), incluyendo el caso negativo sin callback.

Los tests son independientes del orden de ejecucion.
"""
import sys
import unittest
from pathlib import Path

import requests

SCRIPTS_DIR = str(Path(__file__).resolve().parents[1] / "scripts")
LAB_DIR = str(Path(__file__).resolve().parent / "lab")
for p in (SCRIPTS_DIR, LAB_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from core.evidence_engine import EvidenceEngine, VerificationStatus
from core.oob import OOBClient, OOBServer
from pentesting.oob_scanner import OOBScanner
from vulnerable_app import VulnerableApp


class TestOOBServer(unittest.TestCase):
    """OOBServer: registro de callbacks y aislamiento por interaccion."""

    def setUp(self):
        self.oob = OOBServer()
        self.base_url = self.oob.start()

    def tearDown(self):
        self.oob.stop()

    def test_registra_callback(self):
        oob_id = self.oob.new_interaction()
        url = self.oob.url_for(oob_id, suffix="probe")
        requests.get(url, timeout=5)
        callback = self.oob.wait_for_callback(oob_id, timeout=5)
        self.assertIsNotNone(callback)
        assert callback is not None
        self.assertEqual(callback.interaction_id, oob_id)
        self.assertEqual(callback.remote_addr, "127.0.0.1")
        self.assertIn(oob_id, callback.path)

    def test_aislamiento_por_interaction_id(self):
        id1 = self.oob.new_interaction()
        id2 = self.oob.new_interaction()
        requests.get(self.oob.url_for(id1), timeout=5)
        # La interaccion 2 no debe ver el callback de la 1
        self.assertIsNone(self.oob.wait_for_callback(id2, timeout=0.5))
        callback = self.oob.wait_for_callback(id1, timeout=5)
        self.assertIsNotNone(callback)
        assert callback is not None
        self.assertEqual(callback.interaction_id, id1)
        self.assertEqual(self.oob.get_callbacks(id2), [])

    def test_oob_client_con_fetch_inyectado(self):
        server = self.oob
        client = OOBClient(
            new_interaction=server.new_interaction,
            url_for=server.url_for,
            fetch_callbacks=server.get_callbacks,
        )
        oob_id = client.new_interaction()
        url = client.url_for(oob_id)
        requests.get(url, timeout=5)
        callback = client.wait_for_callback(oob_id, timeout=5)
        self.assertIsNotNone(callback)
        assert callback is not None
        self.assertEqual(callback.interaction_id, oob_id)


class TestOOBScannerE2E(unittest.TestCase):
    """E2E: OOBScanner contra el laboratorio vulnerable autorizado."""

    @classmethod
    def setUpClass(cls):
        cls.app = VulnerableApp()
        cls.base_url = cls.app.start()
        cls.oob = OOBServer()
        cls.oob.start()
        cls.evidence_engine = EvidenceEngine()
        cls.scanner = OOBScanner(
            oob_source=cls.oob,
            evidence_engine=cls.evidence_engine,
            timeout=5,
            callback_timeout=10,
        )

    @classmethod
    def tearDownClass(cls):
        cls.oob.stop()
        cls.app.stop()

    def test_ssrf_blind_confirmado_con_callback(self):
        before = len(self.scanner.get_findings())
        results = self.scanner.probe_parameter(
            self.base_url + "/fetch", "url", vuln_types=["ssrf_blind"],
        )
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertTrue(result.is_confirmed)
        self.assertIsNotNone(result.callback)
        assert result.callback is not None
        self.assertEqual(result.callback.interaction_id, result.interaction_id)
        # Finding CONFIRMADO con evidencias
        findings = self.scanner.get_findings()
        self.assertEqual(len(findings), before + 1)
        finding = findings[-1]
        self.assertEqual(finding.vulnerability_type, "ssrf_blind")
        self.assertEqual(finding.verification_status, VerificationStatus.CONFIRMED)
        self.assertGreaterEqual(len(finding.evidences), 2)

    def test_sin_callback_no_confirma(self):
        # Sonda negativa: el numero de findings no crece sin callback
        before = len(self.scanner.get_findings())
        results = self.scanner.probe_parameter(
            self.base_url + "/private/", "url", vuln_types=["ssrf_blind"],
        )
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].is_confirmed)
        self.assertIsNone(results[0].callback)
        self.assertEqual(len(self.scanner.get_findings()), before)


if __name__ == "__main__":
    unittest.main()
