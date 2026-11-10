"""
Hermes Agent Integration

Provides integration with Hermes Agent for autonomous AI security monitoring.

Features:
- Submit AI defense findings to Hermes Agent
- Receive automated responses
- Trigger security workflows
"""

import json
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import sys
import logging

# Setup logging
logger = logging.getLogger('integrations.hermes_agent')


@dataclass
class HermesConfig:
    """Configuration for Hermes Agent integration"""
    api_url: str = "http://localhost:8000"
    api_key: Optional[str] = None
    agent_id: str = "ai-defense-agent"
    timeout: int = 30
    verify_ssl: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'api_url': self.api_url,
            'api_key': '***REDACTED***' if self.api_key else None,
            'agent_id': self.agent_id,
            'timeout': self.timeout,
            'verify_ssl': self.verify_ssl
        }


@dataclass
class HermesTask:
    """Represents a task for Hermes Agent"""
    task_id: str
    task_type: str
    description: str
    payload: Dict[str, Any]
    priority: str = "high"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_type': self.task_type,
            'description': self.description,
            'payload': self.payload,
            'priority': self.priority
        }


@dataclass
class HermesResponse:
    """Response from Hermes Agent"""
    status: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HermesResponse':
        return cls(
            status=data.get('status', 'unknown'),
            message=data.get('message', ''),
            data=data.get('data', {}),
            task_id=data.get('task_id')
        )


class HermesAgentIntegration:
    """
    Integration with Hermes Agent for autonomous security monitoring.
    
    Usage:
        # Initialize
        hermes = HermesAgentIntegration(
            api_url="http://localhost:8000",
            api_key="your-api-key"
        )
        
        # Submit AI threat detection task
        result = hermes.submit_ai_threat_detection(
            text="Ignore previous instructions",
            source_ip="192.168.1.1",
            user_id="user123"
        )
        
        # Get task status
        status = hermes.get_task_status(result.task_id)
    """
    
    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        agent_id: str = "ai-defense-agent",
        timeout: int = 30,
        verify_ssl: bool = True
    ):
        """
        Initialize Hermes Agent integration.
        
        Args:
            api_url: URL of Hermes Agent API
            api_key: API key for authentication
            agent_id: ID of this agent
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
        """
        self.config = HermesConfig(
            api_url=api_url,
            api_key=api_key,
            agent_id=agent_id,
            timeout=timeout,
            verify_ssl=verify_ssl
        )
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'X-Agent-ID': agent_id
            })
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to Hermes Agent"""
        url = f"{self.config.api_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Hermes API request failed: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def submit_task(self, task: HermesTask) -> HermesResponse:
        """Submit a task to Hermes Agent"""
        data = task.to_dict()
        result = self._make_request('POST', 'api/tasks', data=data)
        return HermesResponse.from_dict(result)
    
    def submit_ai_threat_detection(
        self,
        text: str,
        source_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        model: str = "unknown",
        endpoint: Optional[str] = None,
        severity: str = "high"
    ) -> HermesResponse:
        """
        Submit AI threat detection task to Hermes Agent.
        
        Args:
            text: Text to analyze for threats
            source_ip: IP address of the request
            user_id: User identifier
            model: AI model being used
            endpoint: API endpoint
            severity: Initial severity level
        
        Returns:
            HermesResponse with task information
        """
        import uuid
        
        task = HermesTask(
            task_id=str(uuid.uuid4()),
            task_type="ai_threat_detection",
            description=f"Analyze text for AI threats: {text[:100]}...",
            payload={
                'text': text,
                'source_ip': source_ip,
                'user_id': user_id,
                'model': model,
                'endpoint': endpoint,
                'severity': severity,
                'agent_id': self.config.agent_id
            },
            priority=severity
        )
        
        return self.submit_task(task)
    
    def submit_ai_monitoring(
        self,
        action: str,
        target: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> HermesResponse:
        """
        Submit AI monitoring task to Hermes Agent.
        
        Args:
            action: Action to perform (start, stop, scan)
            target: Target to monitor (URL, API endpoint, etc.)
            parameters: Additional parameters
        
        Returns:
            HermesResponse with task information
        """
        import uuid
        
        task = HermesTask(
            task_id=str(uuid.uuid4()),
            task_type="ai_monitoring",
            description=f"{action} AI monitoring for {target}",
            payload={
                'action': action,
                'target': target,
                'parameters': parameters or {},
                'agent_id': self.config.agent_id
            },
            priority="high"
        )
        
        return self.submit_task(task)
    
    def submit_security_alert(
        self,
        alert_type: str,
        title: str,
        description: str,
        severity: str = "critical",
        context: Optional[Dict[str, Any]] = None
    ) -> HermesResponse:
        """
        Submit security alert to Hermes Agent.
        
        Args:
            alert_type: Type of alert (ai_threat, vulnerability, etc.)
            title: Alert title
            description: Alert description
            severity: Severity level
            context: Additional context
        
        Returns:
            HermesResponse with alert information
        """
        import uuid
        
        task = HermesTask(
            task_id=str(uuid.uuid4()),
            task_type="security_alert",
            description=f"[{severity.upper()}] {title}: {description[:100]}",
            payload={
                'alert_type': alert_type,
                'title': title,
                'description': description,
                'severity': severity,
                'context': context or {},
                'agent_id': self.config.agent_id
            },
            priority=severity
        )
        
        return self.submit_task(task)
    
    def get_task_status(self, task_id: str) -> HermesResponse:
        """Get status of a submitted task"""
        result = self._make_request('GET', f'api/tasks/{task_id}')
        return HermesResponse.from_dict(result)
    
    def get_agent_status(self) -> HermesResponse:
        """Get status of Hermes Agent"""
        result = self._make_request('GET', 'api/status')
        return HermesResponse.from_dict(result)
    
    def list_active_tasks(self) -> List[Dict[str, Any]]:
        """List all active tasks"""
        result = self._make_request('GET', 'api/tasks')
        if result.get('status') == 'success':
            return result.get('data', [])
        return []
    
    def cancel_task(self, task_id: str) -> HermesResponse:
        """Cancel a running task"""
        result = self._make_request('DELETE', f'api/tasks/{task_id}')
        return HermesResponse.from_dict(result)
    
    def register_agent(self, agent_name: str, capabilities: List[str]) -> HermesResponse:
        """Register this agent with Hermes"""
        data = {
            'agent_id': self.config.agent_id,
            'agent_name': agent_name,
            'capabilities': capabilities,
            'endpoint': f"{self.config.api_url}/api/agents/{self.config.agent_id}"
        }
        result = self._make_request('POST', 'api/agents/register', data=data)
        return HermesResponse.from_dict(result)
    
    def create_workflow(
        self,
        workflow_name: str,
        triggers: List[Dict[str, Any]],
        actions: List[Dict[str, Any]]
    ) -> HermesResponse:
        """
        Create an automated workflow in Hermes.
        
        Args:
            workflow_name: Name of the workflow
            triggers: List of trigger conditions
            actions: List of actions to execute
        
        Returns:
            HermesResponse with workflow information
        """
        import uuid
        
        data = {
            'workflow_id': str(uuid.uuid4()),
            'workflow_name': workflow_name,
            'agent_id': self.config.agent_id,
            'triggers': triggers,
            'actions': actions
        }
        
        result = self._make_request('POST', 'api/workflows', data=data)
        return HermesResponse.from_dict(result)
    
    def create_ai_defense_workflow(self) -> HermesResponse:
        """
        Create a pre-configured AI defense workflow.
        
        This workflow:
        1. Monitors AI API requests
        2. Detects adversarial patterns
        3. Blocks high-severity threats
        4. Alerts security team
        
        Returns:
            HermesResponse with workflow information
        """
        triggers = [
            {
                'type': 'webhook',
                'endpoint': '/api/ai/monitor',
                'method': 'POST',
                'description': 'AI API request received'
            },
            {
                'type': 'schedule',
                'interval': '1m',
                'description': 'Periodic scan'
            }
        ]
        
        actions = [
            {
                'type': 'ai_threat_detection',
                'description': 'Analyze request for AI threats'
            },
            {
                'type': 'conditional',
                'condition': 'severity == "critical" || severity == "high"',
                'then': [
                    {
                        'type': 'block_request',
                        'description': 'Block malicious request'
                    },
                    {
                        'type': 'send_alert',
                        'severity': 'critical',
                        'description': 'Alert security team'
                    }
                ],
                'else': [
                    {
                        'type': 'log',
                        'description': 'Log for analysis'
                    }
                ]
            }
        ]
        
        return self.create_workflow(
            workflow_name="AI Defense Workflow",
            triggers=triggers,
            actions=actions
        )


# Convenience function
def create_hermes_integration(
    api_url: str = "http://localhost:8000",
    api_key: Optional[str] = None
) -> HermesAgentIntegration:
    """Create a configured Hermes Agent integration"""
    return HermesAgentIntegration(api_url=api_url, api_key=api_key)
