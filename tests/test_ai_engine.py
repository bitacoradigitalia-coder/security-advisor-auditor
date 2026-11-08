"""
Unit tests for the AI Engine (FASE 5, issue #3)
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from core.ai_engine import AIEngine, PriorityAssessment, PriorityLevel
from core.evidence_engine import ConfidenceLevel, Finding, VerificationStatus


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        name="SQL Injection",
        severity="high",
        confidence=ConfidenceLevel.MEDIUM,
        verification_status=VerificationStatus.CANDIDATE,
        target="https://example.com",
        vulnerability_type="sqli",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestAIEngine(unittest.TestCase):
    def setUp(self):
        self.engine = AIEngine()

    def test_confirmed_critical_scores_high(self):
        f = make_finding(
            severity="critical",
            confidence=ConfidenceLevel.CONFIRMED,
            verification_status=VerificationStatus.CONFIRMED,
            reproduction_steps=["paso 1"],
            payload="' OR 1=1--",
        )
        a = self.engine.prioritize_finding(f)
        self.assertEqual(a.priority, PriorityLevel.P0)
        self.assertGreater(a.risk_score, 75)
        self.assertTrue(a.rationale)

    def test_false_positive_discarded(self):
        f = make_finding(verification_status=VerificationStatus.FALSE_POSITIVE, confidence=ConfidenceLevel.FALSE)
        a = self.engine.prioritize_finding(f)
        self.assertEqual(a.priority, PriorityLevel.P4)
        self.assertEqual(a.risk_score, 0.0)
        self.assertIn("falso positivo", a.recommended_action.lower())

    def test_low_severity_lands_in_backlog(self):
        f = make_finding(severity="info", confidence=ConfidenceLevel.LOW, verification_status=VerificationStatus.NOT_VERIFIED)
        a = self.engine.prioritize_finding(f)
        self.assertIn(a.priority, (PriorityLevel.P3, PriorityLevel.P4))
        self.assertLess(a.risk_score, 35)

    def test_ordering_descending(self):
        critical = make_finding(severity="critical", confidence=ConfidenceLevel.CONFIRMED, verification_status=VerificationStatus.CONFIRMED, name="RCE")
        medium = make_finding(severity="medium", confidence=ConfidenceLevel.LOW, verification_status=VerificationStatus.NOT_VERIFIED, name="Header")
        low = make_finding(severity="info", name="Info")
        assessments = self.engine.prioritize_findings([low, medium, critical])
        self.assertEqual(assessments[0].finding_id, critical.finding_id)
        self.assertEqual(assessments[-1].finding_id, low.finding_id)

    def test_correlation_bonus(self):
        f1 = make_finding(name="XSS a", vulnerability_type="xss")
        f2 = make_finding(name="XSS b", vulnerability_type="xss")
        solo = make_finding(name="Solo", vulnerability_type="ssrf")
        assessments = self.engine.prioritize_findings([f1, f2, solo])
        by_id = {a.finding_id: a for a in assessments}
        self.assertEqual(len(by_id[f1.finding_id].correlated_with), 1)
        self.assertEqual(len(by_id[solo.finding_id].correlated_with), 0)
        self.assertGreater(by_id[f1.finding_id].risk_score, by_id[solo.finding_id].risk_score)

    def test_top_n(self):
        findings = [make_finding(name="f" + str(i), severity="high" if i % 2 == 0 else "low") for i in range(10)]
        top = self.engine.get_top(findings, 3)
        self.assertEqual(len(top), 3)
        scores = [a.risk_score for a in top]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_summary_report(self):
        findings = [
            make_finding(name="critical", severity="critical", confidence=ConfidenceLevel.CONFIRMED, verification_status=VerificationStatus.CONFIRMED),
            make_finding(name="fp", verification_status=VerificationStatus.FALSE_POSITIVE, confidence=ConfidenceLevel.FALSE),
            make_finding(name="medium", severity="medium"),
        ]
        report = self.engine.summary_report(findings)
        self.assertEqual(report["total"], 3)
        self.assertEqual(len(report["p0_ids"]), 1)
        self.assertEqual(report["false_positives"], 1)
        self.assertIn("by_priority", report)

    def test_assessment_serialization(self):
        f = make_finding()
        a = self.engine.prioritize_finding(f)
        d = a.to_dict()
        self.assertIn("risk_score", d)
        self.assertIn("priority", d)
        self.assertIn("rationale", d)

    def test_recommendations_by_priority(self):
        for priority, expected in [
            (PriorityLevel.P0, "Remediar inmediatamente"),
            (PriorityLevel.P1, "Programar remediacion"),
            (PriorityLevel.P2, "Planificar remediacion"),
            (PriorityLevel.P3, "backlog"),
        ]:
            f = make_finding()
            action = self.engine._recommend(priority, f)
            self.assertIn(expected.lower(), action.lower())


if __name__ == "__main__":
    unittest.main()
