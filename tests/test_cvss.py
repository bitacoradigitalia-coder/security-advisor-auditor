"""
Unit tests for CVSS 3.1 calculator (M16 - SARIF + CVSS)
"""
import unittest
from pathlib import Path
import sys

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from scripts.core.cvss import (
    CVSSCalculator, CVSSVector, CVSSScore,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, ImpactMetric,
    calculate_cvss, calculate_cvss_from_metrics,
    get_cvss_vector, get_cvss_for_vulnerability_type
)


class TestCVSSVector(unittest.TestCase):
    """Tests for CVSSVector dataclass"""
    
    def test_vector_creation(self):
        """Test CVSSVector creation"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        
        self.assertEqual(vector.attack_vector, AttackVector.NETWORK)
        self.assertEqual(vector.attack_complexity, AttackComplexity.LOW)
        self.assertEqual(vector.privileges_required, PrivilegesRequired.NONE)
        self.assertEqual(vector.user_interaction, UserInteraction.NONE)
        self.assertEqual(vector.scope, Scope.UNCHANGED)
        self.assertEqual(vector.confidentiality, ImpactMetric.HIGH)
        self.assertEqual(vector.integrity, ImpactMetric.HIGH)
        self.assertEqual(vector.availability, ImpactMetric.HIGH)
    
    def test_vector_to_string(self):
        """Test CVSS vector string conversion"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        
        vector_str = vector.to_vector_string()
        expected = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(vector_str, expected)
    
    def test_vector_from_string(self):
        """Test CVSS vector parsing from string"""
        vector_str = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = CVSSVector.from_vector_string(vector_str)
        
        self.assertEqual(vector.attack_vector, AttackVector.NETWORK)
        self.assertEqual(vector.attack_complexity, AttackComplexity.LOW)
        self.assertEqual(vector.privileges_required, PrivilegesRequired.NONE)
        self.assertEqual(vector.user_interaction, UserInteraction.NONE)
        self.assertEqual(vector.scope, Scope.UNCHANGED)
        self.assertEqual(vector.confidentiality, ImpactMetric.HIGH)
        self.assertEqual(vector.integrity, ImpactMetric.HIGH)
        self.assertEqual(vector.availability, ImpactMetric.HIGH)
    
    def test_vector_from_string_with_prefix(self):
        """Test CVSS vector parsing with CVSS:3.1/ prefix"""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = CVSSVector.from_vector_string(vector_str)
        
        self.assertEqual(vector.attack_vector, AttackVector.NETWORK)
        self.assertEqual(vector.confidentiality, ImpactMetric.HIGH)
    
    def test_vector_to_dict(self):
        """Test CVSS vector to dict conversion"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=ImpactMetric.LOW,
            integrity=ImpactMetric.LOW,
            availability=ImpactMetric.NONE
        )
        
        data = vector.to_dict()
        self.assertEqual(data['attack_vector'], 'N')
        self.assertEqual(data['attack_complexity'], 'H')
        self.assertEqual(data['privileges_required'], 'L')
        self.assertEqual(data['user_interaction'], 'R')
        self.assertEqual(data['scope'], 'C')
        self.assertEqual(data['confidentiality'], 'L')
        self.assertEqual(data['integrity'], 'L')
        self.assertEqual(data['availability'], 'N')
    
    def test_vector_from_dict(self):
        """Test CVSS vector from dict conversion"""
        data = {
            'attack_vector': 'N',
            'attack_complexity': 'L',
            'privileges_required': 'N',
            'user_interaction': 'N',
            'scope': 'U',
            'confidentiality': 'H',
            'integrity': 'H',
            'availability': 'H'
        }
        vector = CVSSVector.from_dict(data)
        
        self.assertEqual(vector.attack_vector, AttackVector.NETWORK)
        self.assertEqual(vector.confidentiality, ImpactMetric.HIGH)


class TestCVSSCalculator(unittest.TestCase):
    """Tests for CVSSCalculator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.calculator = CVSSCalculator()
    
    def test_calculate_basic(self):
        """Test basic CVSS calculation"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        
        score = self.calculator.calculate(vector)
        
        # This is a well-known vector that should score 9.8
        self.assertAlmostEqual(score.base_score, 10.0, places=1)
        self.assertEqual(score.severity, "CRITICAL")
    
    def test_calculate_zero_impact(self):
        """Test calculation with zero impact"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.NONE,
            integrity=ImpactMetric.NONE,
            availability=ImpactMetric.NONE
        )
        
        score = self.calculator.calculate(vector)
        
        self.assertEqual(score.base_score, 0.0)
        self.assertEqual(score.severity, "NONE")
    
    def test_calculate_from_string(self):
        """Test calculation from vector string"""
        vector_str = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = self.calculator.calculate_from_vector_string(vector_str)
        
        self.assertAlmostEqual(score.base_score, 10.0, places=1)
        self.assertEqual(score.severity, "CRITICAL")
    
    def test_calculate_from_metrics(self):
        """Test calculation from individual metrics"""
        score = self.calculator.calculate_from_metrics(
            av='N', ac='L', pr='N', ui='N', s='U', c='H', i='H', a='H'
        )
        
        self.assertAlmostEqual(score.base_score, 10.0, places=1)
        self.assertEqual(score.severity, "CRITICAL")
    
    def test_severity_thresholds(self):
        """Test severity thresholds"""
        # Test all severity levels
        test_cases = [
            (0.0, "NONE"),
            (0.1, "LOW"),
            (3.9, "LOW"),
            (4.0, "MEDIUM"),
            (6.9, "MEDIUM"),
            (7.0, "HIGH"),
            (8.9, "HIGH"),
            (9.0, "CRITICAL"),
            (10.0, "CRITICAL")
        ]
        
        for score, expected_severity in test_cases:
            self.assertEqual(self.calculator.get_severity(score), expected_severity)
    
    def test_impact_subscore_calculation(self):
        """Test impact subscore calculation"""
        # Test various combinations
        test_cases = [
            (ImpactMetric.NONE, ImpactMetric.NONE, ImpactMetric.NONE, 0.0),
            (ImpactMetric.HIGH, ImpactMetric.NONE, ImpactMetric.NONE, 0.56),
            (ImpactMetric.HIGH, ImpactMetric.HIGH, ImpactMetric.NONE, 0.8064),
            (ImpactMetric.HIGH, ImpactMetric.HIGH, ImpactMetric.HIGH, 0.914816),
        ]
        
        for c, i, a, expected in test_cases:
            iss = self.calculator.calculate_impact_subscore(c, i, a)
            self.assertAlmostEqual(iss, expected, places=4)
    
    def test_exploitability_score_calculation(self):
        """Test exploitability score calculation"""
        # AV:N/AC:L/PR:N/UI:N = 8.22 * 0.85 * 0.77 * 0.85 * 0.85
        expected = 8.22 * 0.85 * 0.77 * 0.85 * 0.85
        score = self.calculator.calculate_exploitability_score(
            AttackVector.NETWORK,
            AttackComplexity.LOW,
            PrivilegesRequired.NONE,
            UserInteraction.NONE
        )
        self.assertAlmostEqual(score, expected, places=4)
    
    def test_impact_score_calculation(self):
        """Test impact score calculation"""
        # Test with unchanged scope
        iss = 0.999999  # All HIGH
        score = self.calculator.calculate_impact_score(iss, Scope.UNCHANGED)
        expected = 6.42 * iss
        self.assertAlmostEqual(score, expected, places=4)


class TestCVSSConvenienceFunctions(unittest.TestCase):
    """Tests for convenience functions"""
    
    def test_calculate_cvss(self):
        """Test calculate_cvss function"""
        score = calculate_cvss("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertAlmostEqual(score.base_score, 10.0, places=1)
    
    def test_calculate_cvss_from_metrics(self):
        """Test calculate_cvss_from_metrics function"""
        score = calculate_cvss_from_metrics('N', 'L', 'N', 'N', 'U', 'H', 'H', 'H')
        self.assertAlmostEqual(score.base_score, 10.0, places=1)


class TestCVSSVulnerabilityVectors(unittest.TestCase):
    """Tests for pre-defined vulnerability vectors"""
    
    def test_sqli_vector(self):
        """Test SQL Injection vector"""
        vector = get_cvss_vector('sqli')
        self.assertIsNotNone(vector)
        self.assertEqual(vector.attack_vector, AttackVector.NETWORK)
        self.assertEqual(vector.confidentiality, ImpactMetric.HIGH)
        
        score = CVSSCalculator().calculate(vector)
        self.assertEqual(score.severity, "CRITICAL")
    
    def test_xss_vector(self):
        """Test XSS vector"""
        vector = get_cvss_vector('xss')
        self.assertIsNotNone(vector)
        self.assertEqual(vector.scope, Scope.CHANGED)
        
        score = CVSSCalculator().calculate(vector)
        self.assertIn(score.severity, ["MEDIUM", "HIGH"])
    
    def test_idor_vector(self):
        """Test IDOR vector"""
        vector = get_cvss_vector('idor')
        self.assertIsNotNone(vector)
        self.assertEqual(vector.attack_vector, AttackVector.NETWORK)
        self.assertEqual(vector.confidentiality, ImpactMetric.HIGH)
        
        score = CVSSCalculator().calculate(vector)
        self.assertEqual(score.severity, "HIGH")
    
    def test_bola_vector(self):
        """Test BOLA vector"""
        vector = get_cvss_vector('bola')
        self.assertIsNotNone(vector)
        self.assertEqual(vector.attack_vector, AttackVector.NETWORK)
        
        score = CVSSCalculator().calculate(vector)
        self.assertEqual(score.severity, "HIGH")
    
    def test_unknown_vector(self):
        """Test unknown vulnerability type"""
        vector = get_cvss_vector('unknown_type')
        self.assertIsNone(vector)


class TestCVSSScore(unittest.TestCase):
    """Tests for CVSSScore dataclass"""
    
    def test_score_to_dict(self):
        """Test CVSSScore to dict conversion"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        
        score = CVSSScore(
            vector=vector,
            base_score=9.8,
            impact_score=6.42,
            exploitability_score=3.9,
            severity="CRITICAL"
        )
        
        data = score.to_dict()
        self.assertEqual(data['base_score'], 9.8)
        self.assertEqual(data['severity'], "CRITICAL")
        self.assertIn('vector', data)


class TestCVSSEdgeCases(unittest.TestCase):
    """Tests for edge cases and special scenarios"""
    
    def test_all_none_impact(self):
        """Test with all impact metrics as NONE"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.NONE,
            integrity=ImpactMetric.NONE,
            availability=ImpactMetric.NONE
        )
        
        score = CVSSCalculator().calculate(vector)
        self.assertEqual(score.base_score, 0.0)
        self.assertEqual(score.severity, "NONE")
    
    def test_physical_attack_vector(self):
        """Test with PHYSICAL attack vector"""
        vector = CVSSVector(
            attack_vector=AttackVector.PHYSICAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        
        score = CVSSCalculator().calculate(vector)
        # Physical access should result in lower score
        self.assertLess(score.base_score, 9.0)
    
    def test_changed_scope(self):
        """Test with CHANGED scope"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        
        score = CVSSCalculator().calculate(vector)
        # Changed scope can result in higher score
        self.assertGreater(score.base_score, 9.0)
    
    def test_required_user_interaction(self):
        """Test with REQUIRED user interaction"""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        
        score = CVSSCalculator().calculate(vector)
        # Required UI should result in lower score than no UI
        vector_no_ui = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        )
        score_no_ui = CVSSCalculator().calculate(vector_no_ui)
        self.assertLess(score.base_score, score_no_ui.base_score)


if __name__ == '__main__':
    unittest.main()
