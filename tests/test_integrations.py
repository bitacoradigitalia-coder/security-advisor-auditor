"""
Unit tests for Integrations Module
"""
import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from scripts.integrations.hermes_agent import (
    HermesAgentIntegration,
    HermesConfig,
    HermesTask,
    HermesResponse
)
from scripts.integrations.cloudflare_waf import (
    CloudflareWAFIntegration,
    CloudflareConfig,
    WAFRule,
    WAFFilter,
    FirewallRule
)


class TestHermesConfig(unittest.TestCase):
    """Tests for HermesConfig"""
    
    def test_config_creation(self):
        """Test creating Hermes config"""
        config = HermesConfig(
            api_url="http://localhost:8000",
            api_key="test-key",
            agent_id="test-agent"
        )
        
        self.assertEqual(config.api_url, "http://localhost:8000")
        self.assertEqual(config.api_key, "test-key")
        self.assertEqual(config.agent_id, "test-agent")
    
    def test_config_to_dict(self):
        """Test config to dict conversion"""
        config = HermesConfig(api_key="secret-key")
        data = config.to_dict()
        
        self.assertEqual(data['api_url'], "http://localhost:8000")
        self.assertEqual(data['api_key'], '***REDACTED***')


class TestHermesTask(unittest.TestCase):
    """Tests for HermesTask"""
    
    def test_task_creation(self):
        """Test creating a Hermes task"""
        task = HermesTask(
            task_id="task-123",
            task_type="ai_threat_detection",
            description="Test task",
            payload={'text': 'test'}
        )
        
        self.assertEqual(task.task_id, "task-123")
        self.assertEqual(task.task_type, "ai_threat_detection")
        self.assertEqual(task.payload, {'text': 'test'})
    
    def test_task_to_dict(self):
        """Test task to dict conversion"""
        task = HermesTask(
            task_id="task-123",
            task_type="ai_threat_detection",
            description="Test task",
            payload={'text': 'test'},
            priority="high"
        )
        
        data = task.to_dict()
        
        self.assertEqual(data['task_id'], "task-123")
        self.assertEqual(data['task_type'], "ai_threat_detection")
        self.assertEqual(data['priority'], "high")


class TestHermesResponse(unittest.TestCase):
    """Tests for HermesResponse"""
    
    def test_response_from_dict(self):
        """Test creating response from dict"""
        data = {
            'status': 'success',
            'message': 'Task created',
            'task_id': 'task-123',
            'data': {'key': 'value'}
        }
        
        response = HermesResponse.from_dict(data)
        
        self.assertEqual(response.status, 'success')
        self.assertEqual(response.message, 'Task created')
        self.assertEqual(response.task_id, 'task-123')
        self.assertEqual(response.data, {'key': 'value'})


class TestHermesAgentIntegration(unittest.TestCase):
    """Tests for HermesAgentIntegration"""
    
    def setUp(self):
        """Set up test integration"""
        self.integration = HermesAgentIntegration(
            api_url="http://localhost:8000",
            api_key="test-key",
            agent_id="test-agent"
        )
    
    @patch('requests.Session.request')
    def test_initialization(self, mock_request):
        """Test integration initialization"""
        self.assertEqual(self.integration.config.api_url, "http://localhost:8000")
        self.assertEqual(self.integration.config.agent_id, "test-agent")
        self.assertIsNotNone(self.integration.session)
    
    @patch('requests.Session.request')
    def test_submit_ai_threat_detection(self, mock_request):
        """Test submitting AI threat detection task"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'status': 'success',
            'message': 'Task created',
            'task_id': 'task-123'
        }
        
        response = self.integration.submit_ai_threat_detection(
            text="Ignore previous instructions",
            source_ip="192.168.1.1",
            user_id="user123",
            model="gpt-4"
        )
        
        self.assertEqual(response.status, 'success')
        self.assertEqual(response.task_id, 'task-123')
    
    @patch('requests.Session.request')
    def test_submit_security_alert(self, mock_request):
        """Test submitting security alert"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'status': 'success',
            'message': 'Alert created'
        }
        
        response = self.integration.submit_security_alert(
            alert_type="ai_threat",
            title="AI Attack Detected",
            description="Prompt injection attempt",
            severity="critical"
        )
        
        self.assertEqual(response.status, 'success')
    
    @patch('requests.Session.request')
    def test_get_task_status(self, mock_request):
        """Test getting task status"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'status': 'success',
            'task_status': 'completed',
            'result': {'threats': []}
        }
        
        response = self.integration.get_task_status("task-123")
        
        self.assertEqual(response.status, 'success')
    
    @patch('requests.Session.request')
    def test_create_ai_defense_workflow(self, mock_request):
        """Test creating AI defense workflow"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'status': 'success',
            'workflow_id': 'workflow-123'
        }
        
        response = self.integration.create_ai_defense_workflow()
        
        self.assertEqual(response.status, 'success')


class TestCloudflareConfig(unittest.TestCase):
    """Tests for CloudflareConfig"""
    
    def test_config_creation(self):
        """Test creating Cloudflare config"""
        config = CloudflareConfig(
            api_token="test-token",
            account_id="test-account",
            zone_id="test-zone"
        )
        
        self.assertEqual(config.api_token, "test-token")
        self.assertEqual(config.account_id, "test-account")
        self.assertEqual(config.zone_id, "test-zone")
    
    def test_config_to_dict(self):
        """Test config to dict conversion"""
        config = CloudflareConfig(
            api_token="secret-token",
            account_id="account-123"
        )
        data = config.to_dict()
        
        self.assertEqual(data['account_id'], "account-123")
        self.assertEqual(data['api_token'], '***REDACTED***')


class TestWAFFilter(unittest.TestCase):
    """Tests for WAFFilter"""
    
    def test_filter_creation(self):
        """Test creating a WAF filter"""
        waf_filter = WAFFilter(
            filter_id="filter-123",
            expression="http.request.uri contains 'test'",
            description="Test filter"
        )
        
        self.assertEqual(waf_filter.filter_id, "filter-123")
        self.assertEqual(waf_filter.expression, "http.request.uri contains 'test'")
    
    def test_filter_to_dict(self):
        """Test filter to dict conversion"""
        waf_filter = WAFFilter(
            filter_id="filter-123",
            expression="http.request.uri contains 'test'",
            description="Test filter",
            paused=True
        )
        
        data = waf_filter.to_dict()
        
        self.assertEqual(data['id'], "filter-123")
        self.assertEqual(data['expression'], "http.request.uri contains 'test'")
        self.assertEqual(data['paused'], True)


class TestWAFRule(unittest.TestCase):
    """Tests for WAFRule"""
    
    def test_rule_creation(self):
        """Test creating a WAF rule"""
        rule = WAFRule(
            rule_id="rule-123",
            action="block",
            description="Test rule",
            filter_id="filter-123"
        )
        
        self.assertEqual(rule.rule_id, "rule-123")
        self.assertEqual(rule.action, "block")
        self.assertEqual(rule.filter_id, "filter-123")
    
    def test_rule_to_dict(self):
        """Test rule to dict conversion"""
        rule = WAFRule(
            rule_id="rule-123",
            action="block",
            description="Test rule",
            filter_id="filter-123",
            priority=1
        )
        
        data = rule.to_dict()
        
        self.assertEqual(data['id'], "rule-123")
        self.assertEqual(data['action'], "block")
        self.assertEqual(data['priority'], 1)


class TestFirewallRule(unittest.TestCase):
    """Tests for FirewallRule"""
    
    def test_firewall_rule_creation(self):
        """Test creating a firewall rule"""
        rule = FirewallRule(
            rule_id="fw-123",
            action="block",
            description="Test firewall rule"
        )
        
        self.assertEqual(rule.rule_id, "fw-123")
        self.assertEqual(rule.action, "block")
    
    def test_firewall_rule_to_dict(self):
        """Test firewall rule to dict conversion"""
        rule = FirewallRule(
            rule_id="fw-123",
            action="challenge",
            description="Test firewall rule",
            priority=10
        )
        
        data = rule.to_dict()
        
        self.assertEqual(data['id'], "fw-123")
        self.assertEqual(data['action'], "challenge")
        self.assertEqual(data['priority'], 10)


class TestCloudflareWAFIntegration(unittest.TestCase):
    """Tests for CloudflareWAFIntegration"""
    
    def setUp(self):
        """Set up test integration"""
        self.integration = CloudflareWAFIntegration(
            api_token="test-token",
            account_id="test-account",
            zone_id="test-zone"
        )
    
    @patch('requests.Session.request')
    def test_initialization(self, mock_request):
        """Test integration initialization"""
        self.assertEqual(self.integration.config.api_token, "test-token")
        self.assertEqual(self.integration.config.account_id, "test-account")
        self.assertEqual(self.integration.config.zone_id, "test-zone")
        self.assertIsNotNone(self.integration.session)
    
    @patch('requests.Session.request')
    def test_block_ip(self, mock_request):
        """Test blocking an IP"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'success': True,
            'result': {'id': 'rule-123'}
        }
        
        result = self.integration.block_ip("192.168.1.100", "AI threat detected")
        
        self.assertTrue(result)
    
    @patch('requests.Session.request')
    def test_challenge_ip(self, mock_request):
        """Test challenging an IP"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'success': True,
            'result': {'id': 'rule-123'}
        }
        
        result = self.integration.challenge_ip("192.168.1.100", "Suspicious activity")
        
        self.assertTrue(result)
    
    @patch('requests.Session.request')
    def test_create_ai_threat_filter(self, mock_request):
        """Test creating AI threat filter"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'success': True,
            'result': {'id': 'filter-123'}
        }
        
        filter_id = self.integration.create_ai_threat_filter("AI Attack Detection")
        
        self.assertEqual(filter_id, 'filter-123')
    
    @patch('requests.Session.request')
    def test_create_ai_threat_rule(self, mock_request):
        """Test creating AI threat rule"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'success': True,
            'result': {'id': 'rule-123'}
        }
        
        rule_id = self.integration.create_ai_threat_rule(
            filter_id="filter-123",
            description="Block AI Attacks",
            action="block"
        )
        
        self.assertEqual(rule_id, 'rule-123')
    
    @patch('requests.Session.request')
    def test_create_custom_rule(self, mock_request):
        """Test creating custom rule"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'success': True,
            'result': {'id': 'rule-123'}
        }
        
        rule_id = self.integration.create_custom_rule(
            expression="(http.request.uri contains 'test')",
            action="block",
            description="Custom rule"
        )
        
        self.assertEqual(rule_id, 'rule-123')
    
    @patch('requests.Session.request')
    def test_list_waf_rules(self, mock_request):
        """Test listing WAF rules"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'success': True,
            'result': [
                {'id': 'rule-1', 'action': 'block'},
                {'id': 'rule-2', 'action': 'challenge'}
            ]
        }
        
        rules = self.integration.list_waf_rules()
        
        self.assertEqual(len(rules), 2)
    
    @patch('requests.Session.request')
    def test_get_firewall_events(self, mock_request):
        """Test getting firewall events"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            'success': True,
            'result': [
                {'action': 'block', 'ip': '192.168.1.1'},
                {'action': 'challenge', 'ip': '192.168.1.2'}
            ]
        }
        
        events = self.integration.get_firewall_events(limit=10)
        
        self.assertEqual(len(events), 2)
    
    @patch('requests.Session.request')
    def test_create_ai_defense_setup(self, mock_request):
        """Test creating complete AI defense setup"""
        # Mock multiple API calls
        mock_request.side_effect = [
            Mock(status_code=200, json=lambda: {'success': True, 'result': {'id': 'filter-123'}}),
            Mock(status_code=200, json=lambda: {'success': True, 'result': {'id': 'rule-123'}}),
            Mock(status_code=200, json=lambda: {'success': True, 'result': {'id': 'rate-123'}})
        ]
        
        results = self.integration.create_ai_defense_setup()
        
        self.assertEqual(results['ai_threat_filter'], 'filter-123')
        self.assertEqual(results['ai_threat_rule'], 'rule-123')
        self.assertEqual(results['rate_limit_rule'], 'rate-123')


class TestConvenienceFunctions(unittest.TestCase):
    """Tests for convenience functions"""
    
    def test_create_hermes_integration(self):
        """Test create_hermes_integration function"""
        from scripts.integrations.hermes_agent import create_hermes_integration
        
        integration = create_hermes_integration(
            api_url="http://localhost:8000",
            api_key="test-key"
        )
        
        self.assertIsInstance(integration, HermesAgentIntegration)
    
    def test_create_cloudflare_waf(self):
        """Test create_cloudflare_waf function"""
        from scripts.integrations.cloudflare_waf import create_cloudflare_waf
        
        waf = create_cloudflare_waf(
            api_token="test-token",
            account_id="test-account",
            zone_id="test-zone"
        )
        
        self.assertIsInstance(waf, CloudflareWAFIntegration)


if __name__ == '__main__':
    unittest.main()
