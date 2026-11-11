"""Regression coverage for CLI scope propagation and redirect boundaries."""
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import audit
from pentesting.scanner import ActiveScanner, ScanConfig, ScopeValidationError, AuthorizationError


class ScanControlsTests(unittest.TestCase):
    def test_scope_config_loads_json(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'scope.json'
            config.write_text(json.dumps({'allowed_domains': ['example.com']}), encoding='utf-8')
            with patch('audit.ScopeManager') as manager, patch('audit._handle_active_scan'):
                result = audit.main(['--scope-config', str(config), 'scan',
                                     'https://example.com', '--active', '--output', directory])
            self.assertEqual(result, 0)
            self.assertEqual(manager.call_args.args[0].allowed_domains, ['example.com'])

    def test_scope_initialization_failure_prevents_scan(self):
        with patch('audit.ScopeManager', side_effect=ValueError('invalid config')), \
                patch('audit._handle_active_scan') as scan:
            self.assertEqual(audit.main(['scan', 'https://example.com', '--active',
                                         '--output', 'unused']), 2)
            scan.assert_not_called()

    def test_missing_controls_prevent_network_scan(self):
        with patch('audit.SCOPE_AVAILABLE', False), patch('audit._handle_active_scan') as scan:
            self.assertEqual(audit.main(['scan', 'https://example.com', '--active',
                                         '--output', 'unused']), 2)
            scan.assert_not_called()

    def test_explicit_engagement_survives_scope_opt_out(self):
        with patch('audit.EngagementManager') as manager, patch('audit._handle_active_scan') as scan:
            self.assertEqual(audit.main(['--no-scope-validation', '--engagement-id', 'eng-1',
                                         'scan', 'https://example.com', '--active',
                                         '--output', 'unused']), 0)
            self.assertIs(scan.call_args.args[2], manager.return_value)
            self.assertEqual(scan.call_args.args[3], 'eng-1')

    def test_scan_passes_scope_and_engagement(self):
        scope = Mock()
        with tempfile.TemporaryDirectory() as output, \
                patch('audit.ScopeManager', return_value=scope), \
                patch('audit.EngagementManager') as engagement, \
                patch('pentesting.scanner.ActiveScanner') as scanner:
            scanner.return_value.scan.return_value = {}
            self.assertEqual(audit.main(['--engagement-id', 'eng-1', 'scan', 'https://example.com',
                                         '--active', '--output', output]), 0)
            self.assertIs(scanner.call_args.kwargs['scope_manager'], scope)
            self.assertIs(scanner.call_args.kwargs['engagement_manager'], engagement.return_value)
            self.assertEqual(scanner.call_args.kwargs['engagement_id'], 'eng-1')

    def test_scan_fuzz_uses_its_own_parser_and_scope(self):
        scope = Mock()
        with tempfile.TemporaryDirectory() as output, \
                patch('audit.ScopeManager', return_value=scope), \
                patch('pentesting.fuzzer.Fuzzer') as fuzzer:
            fuzzer.return_value.fuzz.return_value = []
            fuzzer.return_value.get_vulnerable_results.return_value = []
            result = audit.main(['scan', 'https://example.com', '--fuzz',
                                 '--fuzz-params', 'id, name', '--output', output])
            self.assertEqual(result, 0)
            self.assertEqual(fuzzer.call_args.args[0].parameters, ['id', 'name'])
            self.assertIs(fuzzer.call_args.kwargs['scope_manager'], scope)

    def test_rejected_redirect_is_never_sent(self):
        scope = Mock()
        scope.validate_target.return_value = ('https://example.com/', [], None)
        scope.validate_redirect.side_effect = ScopeValidationError('outside scope')
        scanner = ActiveScanner(ScanConfig(target='https://example.com/'), scope_manager=scope)
        redirect = requests.Response()
        redirect.status_code = 302
        redirect._content = b''
        redirect._content_consumed = True
        redirect.url = 'https://example.com/'
        redirect._next = requests.Request('GET', 'https://blocked.example/').prepare()
        scanner.session = Mock()
        scanner.session.max_redirects = 30
        scanner.session.request.return_value = redirect
        self.assertIsNone(scanner._make_request('https://example.com/'))
        self.assertFalse(scanner.session.request.call_args.kwargs['allow_redirects'])
        scanner.session.send.assert_not_called()

    def test_rejected_initial_target_is_never_sent(self):
        scope = Mock()
        scope.validate_target.side_effect = ScopeValidationError('outside scope')
        scanner = ActiveScanner(ScanConfig(target='https://blocked.example/'), scope_manager=scope)
        scanner.session = Mock()
        self.assertIsNone(scanner._make_request('https://blocked.example/'))
        scanner.session.request.assert_not_called()

    def test_real_requests_prepares_redirect_before_scope_rejection(self):
        scope = Mock()
        scope.validate_target.return_value = ('https://example.com/', [], None)
        scope.validate_redirect.side_effect = ScopeValidationError('outside scope')
        scanner = ActiveScanner(ScanConfig(target='https://example.com/'), scope_manager=scope)
        sent = []

        class RedirectAdapter(requests.adapters.BaseAdapter):
            def send(self, request, **kwargs):
                sent.append(request.url)
                response = requests.Response()
                response.status_code = 302
                response.url = request.url
                response.request = request
                response.headers['Location'] = 'https://blocked.example/'
                response._content = b''
                response._content_consumed = True
                return response

            def close(self):
                pass

        scanner.session.mount('https://', RedirectAdapter())
        self.assertIsNone(scanner._make_request('https://example.com/'))
        self.assertEqual(sent, ['https://example.com/'])
        scope.validate_redirect.assert_called_once_with('https://example.com/', 'https://blocked.example/')

    def test_engagement_rejects_redirect_before_send(self):
        engagement = Mock()
        engagement.validate.side_effect = [None, AuthorizationError('redirect denied')]
        scanner = ActiveScanner(ScanConfig(target='https://example.com/'),
                                engagement_manager=engagement, engagement_id='eng-1')
        redirect = requests.Response()
        redirect.status_code = 302
        redirect._content = b''
        redirect._content_consumed = True
        redirect.url = 'https://example.com/'
        redirect._next = requests.Request('GET', 'https://example.com/private').prepare()
        scanner.session = Mock()
        scanner.session.max_redirects = 30
        scanner.session.request.return_value = redirect
        self.assertIsNone(scanner._make_request('https://example.com/'))
        scanner.session.send.assert_not_called()

    def test_allowed_redirect_preserves_prepared_request_and_history(self):
        scanner = ActiveScanner(ScanConfig(target='https://example.com/'))
        first = requests.Response()
        first.status_code = 302
        first.url = 'https://example.com/'
        first._next = requests.Request('GET', 'https://example.com/next').prepare()
        final = requests.Response()
        final.status_code = 200
        scanner.session = Mock()
        scanner.session.max_redirects = 30
        scanner.session.request.return_value = first
        scanner.session.send.return_value = final
        self.assertIs(scanner._make_request(first.url), final)
        self.assertEqual(final.history, [first])
        self.assertIs(scanner.session.send.call_args.args[0], first.next)


if __name__ == '__main__':
    unittest.main()
