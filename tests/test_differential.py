"""
Unit tests for differential testing module (M15 - IDOR/BOLA detection)
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock, Mock
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

# Import modules under test
from pentesting.differential import (
    DifferentialTester, DifferentialConfig, DifferentialResult,
    create_differential_tester
)
from pentesting.auth import AuthManager, SessionConfig

# Import core components for evidence
try:
    from scripts.core.evidence_engine import (
        Evidence, EvidenceType, Finding,
        ConfidenceLevel, VerificationStatus
    )
    EVIDENCE_AVAILABLE = True
except ImportError:
    EVIDENCE_AVAILABLE = False


class TestDifferentialResult(unittest.TestCase):
    """Tests for DifferentialResult dataclass"""
    
    def test_differential_result_defaults(self):
        """Test DifferentialResult with default values"""
        result = DifferentialResult(
            endpoint="/api/users/1",
            method="GET",
            session1_name="admin",
            session2_name="user",
            status1=200,
            status2=200,
            content_length1=100,
            content_length2=100
        )
        self.assertEqual(result.endpoint, "/api/users/1")
        self.assertEqual(result.method, "GET")
        self.assertEqual(result.session1_name, "admin")
        self.assertEqual(result.session2_name, "user")
        self.assertEqual(result.status1, 200)
        self.assertEqual(result.status2, 200)
        self.assertFalse(result.is_vulnerable)
        self.assertIsNone(result.vulnerability_type)
        self.assertEqual(result.severity, "medium")
        self.assertEqual(result.differences, [])
        self.assertEqual(result.sensitive_fields, [])
    
    def test_differential_result_to_dict(self):
        """Test DifferentialResult serialization to dict"""
        result = DifferentialResult(
            endpoint="/api/users/1",
            method="GET",
            session1_name="admin",
            session2_name="user",
            status1=200,
            status2=403,
            content_length1=100,
            content_length2=20,
            is_vulnerable=True,
            vulnerability_type="IDOR",
            severity="high",
            differences=["Status code divergence"],
            sensitive_fields=["password"]
        )
        data = result.to_dict()
        self.assertEqual(data['endpoint'], "/api/users/1")
        self.assertEqual(data['vulnerability_type'], "IDOR")
        self.assertEqual(data['severity'], "high")
        self.assertTrue(data['is_vulnerable'])
        self.assertEqual(data['differences'], ["Status code divergence"])


class TestDifferentialConfig(unittest.TestCase):
    """Tests for DifferentialConfig dataclass"""
    
    def test_differential_config_defaults(self):
        """Test DifferentialConfig with default values"""
        config = DifferentialConfig(
            session1_name="admin",
            session2_name="user",
            target="https://example.com"
        )
        self.assertEqual(config.session1_name, "admin")
        self.assertEqual(config.session2_name, "user")
        self.assertEqual(config.target, "https://example.com")
        self.assertEqual(config.methods, ["GET", "POST", "PUT", "DELETE"])
        self.assertEqual(config.max_concurrent, 5)
        self.assertEqual(config.timeout, 30)
        self.assertEqual(config.delay_between_requests, 0.5)
        self.assertTrue(config.check_json_structure)
        self.assertTrue(config.check_status_codes)
    
    def test_differential_config_custom(self):
        """Test DifferentialConfig with custom values"""
        config = DifferentialConfig(
            session1_name="admin",
            session2_name="user",
            target="https://example.com",
            methods=["GET", "POST"],
            max_concurrent=10,
            timeout=60,
            delay_between_requests=1.0,
            check_json_structure=False
        )
        self.assertEqual(config.methods, ["GET", "POST"])
        self.assertEqual(config.max_concurrent, 10)
        self.assertEqual(config.timeout, 60)
        self.assertEqual(config.delay_between_requests, 1.0)
        self.assertFalse(config.check_json_structure)


class TestDifferentialTester(unittest.TestCase):
    """Tests for DifferentialTester class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.temp_dir, 'test.json')
        
        # Create auth manager with test sessions
        self.auth_manager = AuthManager(storage_path=self.storage_path)
        
        # Add test sessions
        self.auth_manager.add_session(
            name="admin",
            base_url="https://example.com",
            auth_type="bearer",
            token="admin_token_123"
        )
        self.auth_manager.add_session(
            name="user",
            base_url="https://example.com",
            auth_type="bearer",
            token="user_token_456"
        )
        
        # Create differential tester
        self.tester = DifferentialTester(
            auth_manager=self.auth_manager,
            storage_path=self.storage_path
        )
        
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test DifferentialTester initialization"""
        self.assertIsNotNone(self.tester.auth_manager)
        self.assertEqual(len(self.tester.sessions), 2)
        self.assertIn("admin", self.tester.sessions)
        self.assertIn("user", self.tester.sessions)
    
    def test_get_session_headers_bearer(self):
        """Test getting headers for bearer token session"""
        headers = self.tester._get_session_headers("admin")
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer admin_token_123")
        self.assertIn("User-Agent", headers)
    
    def test_get_session_headers_cookie(self):
        """Test getting headers for cookie session"""
        self.auth_manager.add_session(
            name="cookie_session",
            cookies={"session_id": "12345"},
            auth_type="cookie"
        )
        headers = self.tester._get_session_headers("cookie_session")
        self.assertIn("Cookie", headers)
        self.assertIn("session_id=12345", headers["Cookie"])
    
    def test_get_session_headers_nonexistent(self):
        """Test getting headers for non-existent session"""
        with self.assertRaises(ValueError) as context:
            self.tester._get_session_headers("nonexistent")
        self.assertIn("not found", str(context.exception))
    
    @patch('requests.request')
    def test_execute_request_success(self, mock_request):
        """Test successful request execution"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"data": "test"}'
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_request.return_value = mock_response
        
        # Execute request
        response, error = self.tester._execute_request(
            url="https://example.com/api/test",
            method="GET",
            session_name="admin"
        )
        
        self.assertIsNone(error)
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)
        
        # Verify headers were passed
        call_args = mock_request.call_args
        self.assertIn("Authorization", call_args[1]['headers'])
    
    @patch('requests.request')
    def test_execute_request_out_of_scope(self, mock_request):
        """Test request blocked by scope validation"""
        # Mock scope manager to reject all URLs
        mock_scope_manager = Mock()
        mock_scope_manager.validate_url.return_value = False
        
        tester = DifferentialTester(
            auth_manager=self.auth_manager,
            scope_manager=mock_scope_manager,
            storage_path=self.storage_path
        )
        
        response, error = tester._execute_request(
            url="https://evil.com/api/test",
            method="GET",
            session_name="admin"
        )
        
        self.assertIsNone(response)
        self.assertIsNotNone(error)
        self.assertIn("out of scope", error)
    
    def test_compare_responses_status_divergence(self):
        """Test comparison with status code divergence (IDOR indicator)"""
        # Create mock responses
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b'{"id": 1, "email": "admin@example.com", "role": "admin"}'
        resp1.headers = {'Content-Type': 'application/json'}
        resp1.text = '{"id": 1, "email": "admin@example.com", "role": "admin"}'
        
        resp2 = Mock()
        resp2.status_code = 403
        resp2.content = b'{"error": "Forbidden"}'
        resp2.headers = {'Content-Type': 'application/json'}
        resp2.text = '{"error": "Forbidden"}'
        
        result = self.tester._compare_responses(
            resp1, resp2, 
            endpoint="https://example.com/api/users/2",
            method="GET"
        )
        
        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.vulnerability_type, "IDOR")
        self.assertEqual(result.severity, "high")
        self.assertTrue(any("Status code divergence" in diff for diff in result.differences))
    
    def test_compare_responses_content_difference(self):
        """Test comparison with content length difference"""
        # Create mock responses with different content
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b'{"id": 1, "email": "admin@example.com", "password": "secret123"}'
        resp1.headers = {'Content-Type': 'application/json'}
        resp1.text = '{"id": 1, "email": "admin@example.com", "password": "secret123"}'
        
        resp2 = Mock()
        resp2.status_code = 200
        resp2.content = b'{"id": 2, "email": "user@example.com"}'
        resp2.headers = {'Content-Type': 'application/json'}
        resp2.text = '{"id": 2, "email": "user@example.com"}'
        
        result = self.tester._compare_responses(
            resp1, resp2,
            endpoint="https://example.com/api/users/1",
            method="GET"
        )
        
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(any("Content length difference" in diff for diff in result.differences))
    
    def test_compare_responses_json_structure_difference(self):
        """Test comparison with JSON structure differences"""
        # Create mock responses with different JSON structures
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b'{"id": 1, "email": "admin@example.com", "ssn": "123-45-6789"}'
        resp1.headers = {'Content-Type': 'application/json'}
        resp1.text = '{"id": 1, "email": "admin@example.com", "ssn": "123-45-6789"}'
        resp1.json.return_value = {"id": 1, "email": "admin@example.com", "ssn": "123-45-6789"}
        
        resp2 = Mock()
        resp2.status_code = 200
        resp2.content = b'{"id": 2, "email": "user@example.com"}'
        resp2.headers = {'Content-Type': 'application/json'}
        resp2.text = '{"id": 2, "email": "user@example.com"}'
        resp2.json.return_value = {"id": 2, "email": "user@example.com"}
        
        result = self.tester._compare_responses(
            resp1, resp2,
            endpoint="https://example.com/api/users/1",
            method="GET"
        )
        
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(len(result.sensitive_fields) > 0)
        self.assertEqual(result.severity, "critical")
    
    @patch('requests.request')
    def test_test_endpoint_success(self, mock_request):
        """Test testing a single endpoint"""
        # Mock responses
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b'{"data": "admin data"}'
        resp1.headers = {'Content-Type': 'application/json'}
        resp1.text = '{"data": "admin data"}'
        
        resp2 = Mock()
        resp2.status_code = 403
        resp2.content = b'{"error": "Forbidden"}'
        resp2.headers = {'Content-Type': 'application/json'}
        resp2.text = '{"error": "Forbidden"}'
        
        mock_request.side_effect = [resp1, resp2]
        
        result = self.tester.test_endpoint(
            endpoint="https://example.com/api/users/2",
            method="GET",
            session1_name="admin",
            session2_name="user"
        )
        
        self.assertIsNotNone(result)
        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.vulnerability_type, "IDOR")
    
    @patch('requests.request')
    def test_test_endpoints_multiple(self, mock_request):
        """Test testing multiple endpoints"""
        # Mock responses
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b'{"data": "test"}'
        resp1.headers = {'Content-Type': 'application/json'}
        resp1.text = '{"data": "test"}'
        
        resp2 = Mock()
        resp2.status_code = 200
        resp2.content = b'{"data": "test"}'
        resp2.headers = {'Content-Type': 'application/json'}
        resp2.text = '{"data": "test"}'
        
        mock_request.side_effect = [resp1, resp2, resp1, resp2]
        
        config = DifferentialConfig(
            session1_name="admin",
            session2_name="user",
            target="https://example.com",
            endpoints=["/api/users/1", "/api/users/2"],
            methods=["GET"],
            delay_between_requests=0  # No delay for testing
        )
        
        results = self.tester.test_endpoints(config)
        
        self.assertEqual(len(results), 2)
    
    @patch('requests.request')
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_create_finding_from_result(self, mock_request):
        """Test creating a Finding from a DifferentialResult"""
        # Create a vulnerable result
        result = DifferentialResult(
            endpoint="https://example.com/api/users/2",
            method="GET",
            session1_name="admin",
            session2_name="user",
            status1=200,
            status2=403,
            content_length1=100,
            content_length2=20,
            is_vulnerable=True,
            vulnerability_type="IDOR",
            severity="high",
            differences=["Status code divergence: 200 vs 403"],
            sensitive_fields=[]
        )
        
        session1 = SessionConfig(
            name="admin",
            base_url="https://example.com",
            auth_type="bearer",
            token="admin_token"
        )
        session2 = SessionConfig(
            name="user",
            base_url="https://example.com",
            auth_type="bearer",
            token="user_token"
        )
        
        finding = self.tester.create_finding_from_result(result, session1, session2)
        
        self.assertIsNotNone(finding)
        self.assertEqual(finding.name, "IDOR - https://example.com/api/users/2")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.confidence, ConfidenceLevel.HIGH)
        self.assertEqual(finding.verification_status, VerificationStatus.CONFIRMED)
        self.assertEqual(finding.vulnerability_type, "idor")
        self.assertEqual(finding.cwe, 639)  # CWE-639: Authorization Bypass Through User-Controlled Key
        self.assertIn("Differential testing detected", finding.description)
        self.assertEqual(len(finding.evidences), 2)
    
    @patch('requests.request')
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_run_differential_test(self, mock_request):
        """Test running complete differential test"""
        # Mock responses
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b'{"id": 1, "email": "admin@example.com"}'
        resp1.headers = {'Content-Type': 'application/json'}
        resp1.text = '{"id": 1, "email": "admin@example.com"}'
        
        resp2 = Mock()
        resp2.status_code = 403
        resp2.content = b'{"error": "Forbidden"}'
        resp2.headers = {'Content-Type': 'application/json'}
        resp2.text = '{"error": "Forbidden"}'
        
        mock_request.side_effect = [resp1, resp2]
        
        config = DifferentialConfig(
            session1_name="admin",
            session2_name="user",
            target="https://example.com/api/users/2",
            methods=["GET"],
            delay_between_requests=0
        )
        
        findings = self.tester.run_differential_test(config)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "idor")


class TestDifferentialTesterIntegration(unittest.TestCase):
    """Integration tests for DifferentialTester"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.temp_dir, 'test.json')
        
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    def test_create_differential_tester_factory(self):
        """Test factory function"""
        tester = create_differential_tester(storage_path=self.storage_path)
        self.assertIsNotNone(tester)
        self.assertIsInstance(tester, DifferentialTester)


if __name__ == '__main__':
    unittest.main()
