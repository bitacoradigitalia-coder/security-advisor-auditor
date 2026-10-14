"""
Unit tests for bugbounty module (BugBountyManager, FindingPrioritizer, Platform Integrations)
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

# Import modules under test
from bugbounty.manager import BugBountyManager, BugBountyProgram, BugBountyFinding
from bugbounty.prioritizer import FindingPrioritizer, PriorityScore
from bugbounty.platforms import (
    HackerOneIntegration, BugcrowdIntegration, IntigritiIntegration,
    PlatformConfig, PLATFORMS
)


class TestBugBountyProgram(unittest.TestCase):
    """Tests for BugBountyProgram dataclass"""
    
    def test_program_defaults(self):
        """Test BugBountyProgram with default values"""
        program = BugBountyProgram(name="Test Program")
        self.assertEqual(program.name, "Test Program")
        self.assertEqual(program.scope, [])
        self.assertEqual(program.rules, "")
        self.assertEqual(program.platform, "generic")
        self.assertTrue(program.active)
    
    def test_program_to_dict(self):
        """Test BugBountyProgram serialization to dict"""
        program = BugBountyProgram(
            name="Test",
            scope=["*.example.com"],
            platform="hackerone",
            reward_range={"min": 50, "max": 5000}
        )
        data = program.to_dict()
        self.assertEqual(data['name'], "Test")
        self.assertEqual(data['scope'], ["*.example.com"])
        self.assertEqual(data['platform'], "hackerone")
    
    def test_program_from_dict(self):
        """Test BugBountyProgram deserialization from dict"""
        data = {
            'name': 'Test Program',
            'scope': ['*.example.com'],
            'platform': 'hackerone',
            'reward_range': {'min': 100, 'max': 1000}
        }
        program = BugBountyProgram.from_dict(data)
        self.assertEqual(program.name, "Test Program")
        self.assertEqual(program.reward_range, {'min': 100, 'max': 1000})
    
    def test_is_in_scope_exact_match(self):
        """Test scope checking with exact match"""
        program = BugBountyProgram(
            name="Test",
            scope=["example.com"],
            in_scope_assets=["api.example.com"]
        )
        self.assertTrue(program.is_in_scope("example.com"))
        self.assertTrue(program.is_in_scope("api.example.com"))
        self.assertFalse(program.is_in_scope("other.com"))
    
    def test_is_in_scope_wildcard(self):
        """Test scope checking with wildcard"""
        program = BugBountyProgram(
            name="Test",
            scope=["*.example.com"]
        )
        self.assertTrue(program.is_in_scope("api.example.com"))
        self.assertTrue(program.is_in_scope("web.example.com"))
        self.assertFalse(program.is_in_scope("example.com"))


class TestBugBountyFinding(unittest.TestCase):
    """Tests for BugBountyFinding dataclass"""
    
    def test_finding_defaults(self):
        """Test BugBountyFinding with default values"""
        finding = BugBountyFinding(
            title="Test Finding",
            program="Test Program"
        )
        self.assertEqual(finding.title, "Test Finding")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.vulnerability_type, "")
        self.assertEqual(finding.status, "new")
    
    def test_finding_to_dict(self):
        """Test BugBountyFinding serialization"""
        finding = BugBountyFinding(
            title="XSS Vulnerability",
            program="Test Program",
            severity="high",
            vulnerability_type="XSS"
        )
        data = finding.to_dict()
        self.assertEqual(data['title'], "XSS Vulnerability")
        self.assertEqual(data['severity'], "high")


class TestBugBountyManager(unittest.TestCase):
    """Tests for BugBountyManager class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.temp_dir, 'bugbounty.json')
        self.manager = BugBountyManager(storage_path=self.storage_path)
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test BugBountyManager initialization"""
        self.assertEqual(self.manager._programs, {})
        self.assertEqual(self.manager._findings, {})
    
    def test_add_program(self):
        """Test adding a program"""
        program = self.manager.add_program(
            name="Test Program",
            scope=["*.example.com"],
            platform="hackerone"
        )
        self.assertIn("Test Program", self.manager._programs)
        self.assertEqual(program.name, "Test Program")
    
    def test_get_program(self):
        """Test retrieving a program"""
        self.manager.add_program(name="Test Program", scope=["*.example.com"])
        program = self.manager.get_program("Test Program")
        self.assertIsNotNone(program)
        self.assertEqual(program.name, "Test Program")
    
    def test_remove_program(self):
        """Test removing a program"""
        self.manager.add_program(name="Test Program", scope=["*.example.com"])
        result = self.manager.remove_program("Test Program")
        self.assertTrue(result)
        self.assertNotIn("Test Program", self.manager._programs)
    
    def test_list_programs(self):
        """Test listing all programs"""
        self.manager.add_program(name="Program 1", scope=["*.example1.com"])
        self.manager.add_program(name="Program 2", scope=["*.example2.com"])
        programs = self.manager.list_programs()
        self.assertEqual(len(programs), 2)
    
    def test_add_finding(self):
        """Test adding a finding"""
        self.manager.add_program(name="Test Program", scope=["*.example.com"])
        finding = self.manager.add_finding(
            program="Test Program",
            finding={
                'title': 'Test Finding',
                'severity': 'high',
                'vulnerability_type': 'SQLi',
                'target': 'https://example.com'
            }
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.title, "Test Finding")
        self.assertEqual(finding.severity, "high")
    
    def test_get_finding(self):
        """Test retrieving a finding"""
        self.manager.add_program(name="Test Program", scope=["*.example.com"])
        finding = self.manager.add_finding(
            program="Test Program",
            finding={
                'title': 'Test Finding',
                'severity': 'high',
                'target': 'https://example.com'
            }
        )
        retrieved = self.manager.get_finding(finding.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, "Test Finding")
    
    def test_update_finding(self):
        """Test updating a finding"""
        self.manager.add_program(name="Test Program", scope=["*.example.com"])
        finding = self.manager.add_finding(
            program="Test Program",
            finding={
                'title': 'Test Finding',
                'severity': 'high',
                'status': 'new',
                'target': 'https://example.com'
            }
        )
        updated = self.manager.update_finding(
            finding_id=finding.id,
            severity="critical",
            status="triaged"
        )
        self.assertTrue(updated)
        retrieved = self.manager.get_finding(finding.id)
        self.assertEqual(retrieved.severity, "critical")
        self.assertEqual(retrieved.status, "triaged")
    
    def test_remove_finding(self):
        """Test removing a finding"""
        self.manager.add_program(name="Test Program", scope=["*.example.com"])
        finding = self.manager.add_finding(
            program="Test Program",
            finding={
                'title': 'Test Finding',
                'target': 'https://example.com'
            }
        )
        result = self.manager.remove_finding(finding.id)
        self.assertTrue(result)
        self.assertIsNone(self.manager.get_finding(finding.id))
    
    def test_persistence(self):
        """Test that programs and findings are persisted to file"""
        self.manager.add_program(name="Persistent Program", scope=["*.example.com"])
        self.manager.add_finding(
            program="Persistent Program",
            finding={
                'title': 'Persistent Finding',
                'target': 'https://example.com'
            }
        )
        
        # Create a new manager and verify data is loaded
        new_manager = BugBountyManager(storage_path=self.storage_path)
        self.assertIn("Persistent Program", new_manager._programs)
        self.assertEqual(len(new_manager._findings), 1)
    
    def test_get_statistics(self):
        """Test getting statistics"""
        self.manager.add_program(name="Test Program", scope=["*.example.com"])
        self.manager.add_finding(
            program="Test Program",
            finding={
                'title': 'Critical Finding',
                'severity': 'critical',
                'target': 'https://example.com'
            }
        )
        self.manager.add_finding(
            program="Test Program",
            finding={
                'title': 'High Finding',
                'severity': 'high',
                'target': 'https://example.com'
            }
        )
        
        stats = self.manager.get_statistics()
        self.assertEqual(stats['total_programs'], 1)
        self.assertEqual(stats['total_findings'], 2)
        self.assertEqual(stats['findings_by_severity']['critical'], 1)
        self.assertEqual(stats['findings_by_severity']['high'], 1)
    
    def test_list_programs(self):
        """Test listing all programs"""
        self.manager.add_program(name="Program 1", scope=["*.example1.com"])
        self.manager.add_program(name="Program 2", scope=["*.example2.com"])
        programs = self.manager.list_programs()
        self.assertEqual(len(programs), 2)
        self.assertIn("Program 1", programs)
        self.assertIn("Program 2", programs)


class TestFindingPrioritizer(unittest.TestCase):
    """Tests for FindingPrioritizer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.prioritizer = FindingPrioritizer()
    
    def test_default_weights(self):
        """Test default weights sum to 1.0"""
        total = sum(self.prioritizer.DEFAULT_WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=5)
    
    def test_severity_scores(self):
        """Test severity scores are defined"""
        self.assertEqual(self.prioritizer.SEVERITY_SCORES['critical'], 10.0)
        self.assertEqual(self.prioritizer.SEVERITY_SCORES['high'], 7.0)
        self.assertEqual(self.prioritizer.SEVERITY_SCORES['medium'], 5.0)
    
    def test_impact_scores(self):
        """Test impact scores are defined"""
        self.assertEqual(self.prioritizer.IMPACT_SCORES['data_breach'], 10.0)
        self.assertEqual(self.prioritizer.IMPACT_SCORES['rce'], 9.5)
        self.assertEqual(self.prioritizer.IMPACT_SCORES['xss'], 7.0)
    
    def test_prioritize_single_finding(self):
        """Test prioritizing a single finding"""
        finding = {
            'id': '1',
            'severity': 'critical',
            'vulnerability_type': 'sqli',
            'exploitability': 'easy',
            'scope': 'production',
            'confidence': 'confirmed'
        }
        
        scores = self.prioritizer.prioritize([finding])
        self.assertEqual(len(scores), 1)
        score = scores[0]
        self.assertIsInstance(score, PriorityScore)
        self.assertEqual(score.finding_id, '1')
        self.assertEqual(score.severity, 'critical')
        # Critical finding should have high score
        self.assertGreater(score.score, 8.0)
    
    def test_prioritize_multiple_findings(self):
        """Test prioritizing multiple findings"""
        findings = [
            {
                'id': '1',
                'severity': 'critical',
                'vulnerability_type': 'sqli',
                'exploitability': 'easy',
                'scope': 'production',
                'confidence': 'confirmed'
            },
            {
                'id': '2',
                'severity': 'low',
                'vulnerability_type': 'xxe',
                'exploitability': 'hard',
                'scope': 'development',
                'confidence': 'low'
            }
        ]
        
        scores = self.prioritizer.prioritize_multiple(findings)
        self.assertEqual(len(scores), 2)
        
        # Critical finding should be first
        self.assertEqual(scores[0].finding_id, '1')
        # Low finding should be last
        self.assertEqual(scores[1].finding_id, '2')
    
    def test_get_priority_level(self):
        """Test getting priority level from score"""
        self.assertEqual(self.prioritizer.get_priority_level(9.0), 'critical')
        self.assertEqual(self.prioritizer.get_priority_level(7.0), 'high')
        self.assertEqual(self.prioritizer.get_priority_level(5.0), 'medium')
        # Note: The prioritizer uses specific thresholds
        # Based on the implementation: critical >= 8.5, high >= 7.0, medium >= 5.0, low >= 3.0, info < 3.0
        self.assertEqual(self.prioritizer.get_priority_level(4.0), 'low')
        self.assertEqual(self.prioritizer.get_priority_level(2.5), 'info')
        self.assertEqual(self.prioritizer.get_priority_level(1.5), 'info')


class TestPlatformConfig(unittest.TestCase):
    """Tests for PlatformConfig and platform configurations"""
    
    def test_platform_config_defaults(self):
        """Test PlatformConfig with default values"""
        config = PlatformConfig(
            name="Test Platform",
            base_url="https://test.com",
            api_url="https://api.test.com"
        )
        self.assertEqual(config.name, "Test Platform")
        self.assertEqual(config.base_url, "https://test.com")
        self.assertEqual(config.api_url, "https://api.test.com")
    
    def test_platforms_defined(self):
        """Test that platforms are defined"""
        self.assertIn('hackerone', PLATFORMS)
        self.assertIn('bugcrowd', PLATFORMS)
        self.assertIn('intigriti', PLATFORMS)
    
    def test_hackerone_config(self):
        """Test HackerOne platform configuration"""
        config = PLATFORMS['hackerone']
        self.assertEqual(config.name, 'HackerOne')
        self.assertEqual(config.base_url, 'https://www.hackerone.com')
        self.assertEqual(config.api_url, 'https://api.hackerone.com/v1')


class TestHackerOneIntegration(unittest.TestCase):
    """Tests for HackerOneIntegration class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.api_token = "test_token_123"
        self.integration = HackerOneIntegration(api_token=self.api_token)
    
    def test_initialization(self):
        """Test HackerOneIntegration initialization"""
        self.assertEqual(self.integration.api_token, self.api_token)
        self.assertEqual(self.integration.platform, 'hackerone')
        self.assertIsNotNone(self.integration.session)
    
    @patch.object(HackerOneIntegration, '_make_request')
    def test_get_user_info(self, mock_make_request):
        """Test getting user info"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'id': '123',
            'name': 'Test User',
            'username': 'testuser',
            'email': 'test@example.com'
        }
        mock_response.raise_for_status.return_value = None
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        user_info = self.integration.get_user_info()
        self.assertIsNotNone(user_info)
        self.assertEqual(user_info['username'], 'testuser')
        mock_make_request.assert_called_once_with('GET', '/me')


if __name__ == '__main__':
    unittest.main()
