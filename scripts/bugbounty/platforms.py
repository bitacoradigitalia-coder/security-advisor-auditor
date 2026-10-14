"""
Bug Bounty Platform Integrations for Security Advisor Auditor v3.0
Integrates with various Bug Bounty platforms (HackerOne, Bugcrowd, etc.).
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
import requests


@dataclass
class PlatformConfig:
    """Configuration for a Bug Bounty platform."""
    name: str
    base_url: str
    api_url: str
    auth_type: str = "bearer"  # bearer, api_key, basic
    auth_header: str = "Authorization"
    token_prefix: str = "Bearer"
    
    def to_dict(self) -> Dict[str, str]:
        return {
            'name': self.name,
            'base_url': self.base_url,
            'api_url': self.api_url,
            'auth_type': self.auth_type,
            'auth_header': self.auth_header,
            'token_prefix': self.token_prefix
        }


# Platform configurations
PLATFORMS = {
    'hackerone': PlatformConfig(
        name='HackerOne',
        base_url='https://www.hackerone.com',
        api_url='https://api.hackerone.com/v1',
        auth_type='bearer',
        auth_header='Authorization',
        token_prefix='Bearer'
    ),
    'bugcrowd': PlatformConfig(
        name='Bugcrowd',
        base_url='https://www.bugcrowd.com',
        api_url='https://api.bugcrowd.com',
        auth_type='bearer',
        auth_header='Authorization',
        token_prefix='Bearer'
    ),
    'intigriti': PlatformConfig(
        name='Intigriti',
        base_url='https://www.intigriti.com',
        api_url='https://api.intigriti.com',
        auth_type='bearer',
        auth_header='Authorization',
        token_prefix='Bearer'
    ),
    'yeswehack': PlatformConfig(
        name='YesWeHack',
        base_url='https://www.yeswehack.com',
        api_url='https://api.yeswehack.com',
        auth_type='bearer',
        auth_header='Authorization',
        token_prefix='Bearer'
    )
}


class BasePlatformIntegration:
    """
    Base class for Bug Bounty platform integrations.
    """
    
    def __init__(self, api_token: str, platform: str = 'generic'):
        """
        Initialize the platform integration.
        
        Args:
            api_token: API token for authentication
            platform: Platform name
        """
        self.api_token = api_token
        self.platform = platform
        self.config = PLATFORMS.get(platform.lower(), PLATFORMS['hackerone'])
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with authentication."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'SecurityAdvisor/3.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Add authentication header
        if self.config.auth_type == 'bearer':
            session.headers[self.config.auth_header] = \
                f"{self.config.token_prefix} {self.api_token}"
        elif self.config.auth_type == 'api_key':
            session.headers[self.config.auth_header] = self.api_token
        
        return session
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Optional[requests.Response]:
        """
        Make an authenticated request to the platform API.
        
        Args:
            method: HTTP method
            endpoint: API endpoint (appended to base URL)
            data: Request body
            params: Query parameters
        
        Returns:
            Response object or None if failed
        """
        url = f"{self.config.api_url}{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=30
            )
            return response
        except requests.exceptions.RequestException:
            return None
    
    def get_program(self, program_handle: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a program.
        
        Args:
            program_handle: Program handle/identifier
        
        Returns:
            Program information or None
        """
        # To be implemented by subclasses
        return None
    
    def list_programs(self) -> List[Dict[str, Any]]:
        """
        List all accessible programs.
        
        Returns:
            List of programs
        """
        # To be implemented by subclasses
        return []
    
    def submit_report(self, program_handle: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit a vulnerability report.
        
        Args:
            program_handle: Program handle/identifier
            report_data: Report data
        
        Returns:
            Submission result
        """
        # To be implemented by subclasses
        return {}
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a submitted report.
        
        Args:
            report_id: Report ID
        
        Returns:
            Report information or None
        """
        # To be implemented by subclasses
        return None
    
    def update_report(self, report_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update a submitted report.
        
        Args:
            report_id: Report ID
            updates: Updates to apply
        
        Returns:
            True if update was successful
        """
        # To be implemented by subclasses
        return False
    
    def close_report(self, report_id: str, reason: str) -> bool:
        """
        Close a report.
        
        Args:
            report_id: Report ID
            reason: Reason for closing
        
        Returns:
            True if close was successful
        """
        # To be implemented by subclasses
        return False
    
    def list_reports(self, program_handle: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List reports for a program or all programs.
        
        Args:
            program_handle: Program handle (optional)
        
        Returns:
            List of reports
        """
        # To be implemented by subclasses
        return []
    
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the authenticated user.
        
        Returns:
            User information or None
        """
        # To be implemented by subclasses
        return None


class HackerOneIntegration(BasePlatformIntegration):
    """
    Integration with HackerOne platform.
    """
    
    def __init__(self, api_token: str):
        """
        Initialize HackerOne integration.
        
        Args:
            api_token: HackerOne API token
        """
        super().__init__(api_token, 'hackerone')
    
    def get_program(self, program_handle: str) -> Optional[Dict[str, Any]]:
        """
        Get HackerOne program information.
        
        Args:
            program_handle: Program handle
        
        Returns:
            Program information or None
        """
        response = self._make_request('GET', f'/programs/{program_handle}')
        
        if response and response.status_code == 200:
            return response.json()
        
        return None
    
    def list_programs(self) -> List[Dict[str, Any]]:
        """
        List all accessible HackerOne programs.
        
        Returns:
            List of programs
        """
        response = self._make_request('GET', '/programs')
        
        if response and response.status_code == 200:
            data = response.json()
            return data.get('programs', [])
        
        return []
    
    def submit_report(self, program_handle: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit a vulnerability report to HackerOne.
        
        Args:
            program_handle: Program handle
            report_data: Report data
        
        Returns:
            Submission result
        
        Raises:
            ValueError: If required fields are missing
        """
        # Map our finding data to HackerOne format
        payload = self._map_report_to_hackerone(report_data)
        
        response = self._make_request('POST', f'/programs/{program_handle}/reports', data=payload)
        
        if response:
            if response.status_code == 201:
                return response.json()
            elif response.status_code == 400:
                error_data = response.json()
                raise ValueError(f"Invalid report: {error_data.get('message', 'Unknown error')}")
            elif response.status_code == 401:
                raise ValueError("Unauthorized: Invalid API token")
            elif response.status_code == 403:
                raise ValueError("Forbidden: Not allowed to submit to this program")
            elif response.status_code == 404:
                raise ValueError(f"Program not found: {program_handle}")
        
        return {'error': 'Failed to submit report'}
    
    def _map_report_to_hackerone(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map our report data to HackerOne format.
        
        Args:
            report_data: Our report data
        
        Returns:
            HackerOne-compatible report data
        """
        # HackerOne report format
        payload = {
            'title': report_data.get('title', 'Untitled'),
            'vulnerability_type': self._map_vulnerability_type(report_data.get('vulnerability_type', '')),
            'severity': self._map_severity(report_data.get('severity', 'medium')),
            'description': report_data.get('description', ''),
            'steps_to_reproduce': report_data.get('steps_to_reproduce', []),
            'impact': report_data.get('impact', ''),
            'asset_identifier': report_data.get('target', ''),
            'asset_type': 'url',
            'confidentiality_requirement': 'public',
            'integrity_requirement': 'none',
            'availability_requirement': 'none'
        }
        
        # Add optional fields
        if 'cvss_score' in report_data:
            payload['cvss_score'] = report_data['cvss_score']
        
        if 'cvss_vector' in report_data:
            payload['cvss_vector'] = report_data['cvss_vector']
        
        if 'proof_of_concept' in report_data:
            payload['proof_of_concept'] = report_data['proof_of_concept']
        
        if 'remediation' in report_data:
            payload['remediation'] = report_data['remediation']
        
        if 'references' in report_data:
            payload['references'] = report_data['references']
        
        return payload
    
    def _map_vulnerability_type(self, vuln_type: str) -> str:
        """
        Map our vulnerability type to HackerOne's taxonomy.
        
        Args:
            vuln_type: Our vulnerability type
        
        Returns:
            HackerOne vulnerability type
        """
        # Common mappings
        mappings = {
            'sqli': 'sql-injection',
            'sql_injection': 'sql-injection',
            'xss': 'cross-site-scripting',
            'cross_site_scripting': 'cross-site-scripting',
            'ssrf': 'server-side-request-forgery',
            'server_side_request_forgery': 'server-side-request-forgery',
            'rce': 'remote-code-execution',
            'remote_code_execution': 'remote-code-execution',
            'lfi': 'local-file-inclusion',
            'local_file_inclusion': 'local-file-inclusion',
            'rfi': 'remote-file-inclusion',
            'remote_file_inclusion': 'remote-file-inclusion',
            'idor': 'insecure-direct-object-reference',
            'insecure_direct_object_reference': 'insecure-direct-object-reference',
            'xxe': 'xml-external-entity',
            'xml_external_entity': 'xml-external-entity',
            'csrf': 'cross-site-request-forgery',
            'cross_site_request_forgery': 'cross-site-request-forgery',
            'crlf': 'crlf-injection',
            'ssti': 'server-side-template-injection',
            'server_side_template_injection': 'server-side-template-injection',
            'command_injection': 'command-injection',
            'path_traversal': 'path-traversal',
            'open_redirect': 'open-redirect',
            'misconfiguration': 'misconfiguration',
            'information_disclosure': 'information-disclosure',
            'broken_access_control': 'broken-access-control'
        }
        
        return mappings.get(vuln_type.lower(), vuln_type)
    
    def _map_severity(self, severity: str) -> str:
        """
        Map our severity to HackerOne's severity.
        
        Args:
            severity: Our severity level
        
        Returns:
            HackerOne severity level
        """
        mappings = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'none'
        }
        
        return mappings.get(severity.lower(), 'none')
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Get HackerOne report information.
        
        Args:
            report_id: Report ID
        
        Returns:
            Report information or None
        """
        response = self._make_request('GET', f'/reports/{report_id}')
        
        if response and response.status_code == 200:
            return response.json()
        
        return None
    
    def update_report(self, report_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update a HackerOne report.
        
        Args:
            report_id: Report ID
            updates: Updates to apply
        
        Returns:
            True if update was successful
        """
        response = self._make_request('PATCH', f'/reports/{report_id}', data=updates)
        
        return response is not None and response.status_code in [200, 204]
    
    def list_reports(self, program_handle: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List HackerOne reports.
        
        Args:
            program_handle: Program handle (optional)
        
        Returns:
            List of reports
        """
        if program_handle:
            response = self._make_request('GET', f'/programs/{program_handle}/reports')
        else:
            response = self._make_request('GET', '/reports')
        
        if response and response.status_code == 200:
            data = response.json()
            return data.get('reports', [])
        
        return []
    
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """
        Get HackerOne user information.
        
        Returns:
            User information or None
        """
        response = self._make_request('GET', '/me')
        
        if response and response.status_code == 200:
            return response.json()
        
        return None
    
    def add_comment(self, report_id: str, comment: str) -> bool:
        """
        Add a comment to a HackerOne report.
        
        Args:
            report_id: Report ID
            comment: Comment text
        
        Returns:
            True if comment was added
        """
        payload = {
            'message': comment,
            'internal': False
        }
        
        response = self._make_request('POST', f'/reports/{report_id}/comments', data=payload)
        
        return response is not None and response.status_code == 201
    
    def upload_attachment(self, report_id: str, file_path: str, description: str = '') -> bool:
        """
        Upload an attachment to a HackerOne report.
        
        Args:
            report_id: Report ID
            file_path: Path to file to upload
            description: Attachment description
        
        Returns:
            True if upload was successful
        """
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                data = {'description': description}
                
                response = self.session.post(
                    f"{self.config.api_url}/reports/{report_id}/attachments",
                    files=files,
                    data=data,
                    timeout=30
                )
                
                return response is not None and response.status_code == 201
        except IOError:
            return False


class BugcrowdIntegration(BasePlatformIntegration):
    """
    Integration with Bugcrowd platform.
    """
    
    def __init__(self, api_token: str):
        """
        Initialize Bugcrowd integration.
        
        Args:
            api_token: Bugcrowd API token
        """
        super().__init__(api_token, 'bugcrowd')
    
    def get_program(self, program_id: str) -> Optional[Dict[str, Any]]:
        """
        Get Bugcrowd program information.
        
        Args:
            program_id: Program ID
        
        Returns:
            Program information or None
        """
        response = self._make_request('GET', f'/programs/{program_id}')
        
        if response and response.status_code == 200:
            return response.json()
        
        return None
    
    def list_programs(self) -> List[Dict[str, Any]]:
        """
        List all accessible Bugcrowd programs.
        
        Returns:
            List of programs
        """
        response = self._make_request('GET', '/programs')
        
        if response and response.status_code == 200:
            data = response.json()
            return data.get('programs', [])
        
        return []
    
    def submit_report(self, program_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit a vulnerability report to Bugcrowd.
        
        Args:
            program_id: Program ID
            report_data: Report data
        
        Returns:
            Submission result
        """
        # Map our finding data to Bugcrowd format
        payload = self._map_report_to_bugcrowd(report_data)
        
        response = self._make_request('POST', f'/programs/{program_id}/submissions', data=payload)
        
        if response:
            if response.status_code == 201:
                return response.json()
            elif response.status_code == 400:
                error_data = response.json()
                raise ValueError(f"Invalid report: {error_data.get('error', 'Unknown error')}")
            elif response.status_code == 401:
                raise ValueError("Unauthorized: Invalid API token")
            elif response.status_code == 403:
                raise ValueError("Forbidden: Not allowed to submit to this program")
            elif response.status_code == 404:
                raise ValueError(f"Program not found: {program_id}")
        
        return {'error': 'Failed to submit report'}
    
    def _map_report_to_bugcrowd(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map our report data to Bugcrowd format.
        
        Args:
            report_data: Our report data
        
        Returns:
            Bugcrowd-compatible report data
        """
        # Bugcrowd report format
        payload = {
            'title': report_data.get('title', 'Untitled'),
            'description': report_data.get('description', ''),
            'severity': self._map_severity(report_data.get('severity', 'medium')),
            'vulnerability_type': self._map_vulnerability_type(report_data.get('vulnerability_type', '')),
            'steps_to_reproduce': report_data.get('steps_to_reproduce', []),
            'impact': report_data.get('impact', ''),
            'target_url': report_data.get('target', ''),
            'custom_fields': {}
        }
        
        # Add optional fields
        if 'proof_of_concept' in report_data:
            payload['proof_of_concept'] = report_data['proof_of_concept']
        
        if 'remediation' in report_data:
            payload['remediation'] = report_data['remediation']
        
        if 'references' in report_data:
            payload['references'] = report_data['references']
        
        if 'cvss_score' in report_data:
            payload['cvss_score'] = report_data['cvss_score']
        
        return payload
    
    def _map_vulnerability_type(self, vuln_type: str) -> str:
        """
        Map our vulnerability type to Bugcrowd's taxonomy.
        
        Args:
            vuln_type: Our vulnerability type
        
        Returns:
            Bugcrowd vulnerability type
        """
        # Use similar mappings as HackerOne
        mappings = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-site Scripting',
            'ssrf': 'Server Side Request Forgery',
            'rce': 'Remote Code Execution',
            'lfi': 'Local File Inclusion',
            'rfi': 'Remote File Inclusion',
            'idor': 'Insecure Direct Object Reference',
            'xxe': 'XML External Entity',
            'csrf': 'Cross-site Request Forgery',
            'crlf': 'CRLF Injection',
            'ssti': 'Server Side Template Injection',
            'command_injection': 'Command Injection',
            'path_traversal': 'Path Traversal',
            'open_redirect': 'Open Redirect'
        }
        
        return mappings.get(vuln_type.lower(), vuln_type)
    
    def _map_severity(self, severity: str) -> str:
        """
        Map our severity to Bugcrowd's severity.
        
        Args:
            severity: Our severity level
        
        Returns:
            Bugcrowd severity level
        """
        # Bugcrowd uses: critical, high, medium, low, info
        return severity.lower()
    
    def get_report(self, submission_id: str) -> Optional[Dict[str, Any]]:
        """
        Get Bugcrowd submission information.
        
        Args:
            submission_id: Submission ID
        
        Returns:
            Submission information or None
        """
        response = self._make_request('GET', f'/submissions/{submission_id}')
        
        if response and response.status_code == 200:
            return response.json()
        
        return None
    
    def list_reports(self, program_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List Bugcrowd submissions.
        
        Args:
            program_id: Program ID (optional)
        
        Returns:
            List of submissions
        """
        if program_id:
            response = self._make_request('GET', f'/programs/{program_id}/submissions')
        else:
            response = self._make_request('GET', '/submissions')
        
        if response and response.status_code == 200:
            data = response.json()
            return data.get('submissions', [])
        
        return []
    
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """
        Get Bugcrowd user information.
        
        Returns:
            User information or None
        """
        response = self._make_request('GET', '/me')
        
        if response and response.status_code == 200:
            return response.json()
        
        return None


class IntigritiIntegration(BasePlatformIntegration):
    """
    Integration with Intigriti platform.
    """
    
    def __init__(self, api_token: str):
        """
        Initialize Intigriti integration.
        
        Args:
            api_token: Intigriti API token
        """
        super().__init__(api_token, 'intigriti')
        # Intigriti uses API key in X-API-Key header
        self.config.auth_header = 'X-API-Key'
        self.config.token_prefix = ''


# Factory function
def get_platform_integration(platform: str, api_token: str) -> BasePlatformIntegration:
    """
    Get the appropriate platform integration.
    
    Args:
        platform: Platform name (hackerone, bugcrowd, intigriti)
        api_token: API token
    
    Returns:
        Platform integration instance
    
    Raises:
        ValueError: If platform is not supported
    """
    platform = platform.lower()
    
    if platform == 'hackerone':
        return HackerOneIntegration(api_token)
    elif platform == 'bugcrowd':
        return BugcrowdIntegration(api_token)
    elif platform == 'intigriti':
        return IntigritiIntegration(api_token)
    else:
        raise ValueError(f"Platform '{platform}' not supported")
