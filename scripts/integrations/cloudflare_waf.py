"""
Cloudflare WAF Integration

Provides integration with Cloudflare Web Application Firewall (WAF).

Features:
- Create WAF rules based on AI threat detection
- Block malicious IPs
- Rate limiting
- Custom rule management
"""

import json
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import sys
import logging
from datetime import datetime

# Setup logging
logger = logging.getLogger('integrations.cloudflare_waf')


@dataclass
class CloudflareConfig:
    """Configuration for Cloudflare API"""
    api_token: str
    account_id: str
    zone_id: Optional[str] = None
    api_url: str = "https://api.cloudflare.com/client/v4"
    timeout: int = 30
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'api_token': '***REDACTED***' if self.api_token else None,
            'account_id': self.account_id,
            'zone_id': self.zone_id,
            'api_url': self.api_url,
            'timeout': self.timeout
        }


@dataclass
class WAFRule:
    """Represents a Cloudflare WAF rule"""
    rule_id: Optional[str] = None
    action: str = "block"  # block, challenge, allow, log
    description: str = ""
    filter_id: Optional[str] = None
    group_id: Optional[str] = None
    paused: bool = False
    priority: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'action': self.action,
            'description': self.description
        }
        if self.rule_id:
            result['id'] = self.rule_id
        if self.filter_id:
            result['filter'] = {'id': self.filter_id}
        if self.group_id:
            result['group'] = {'id': self.group_id}
        if self.paused:
            result['paused'] = self.paused
        if self.priority:
            result['priority'] = self.priority
        return result


@dataclass
class WAFFilter:
    """Represents a Cloudflare WAF filter"""
    filter_id: Optional[str] = None
    expression: str = ""
    description: str = ""
    paused: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'expression': self.expression,
            'description': self.description
        }
        if self.filter_id:
            result['id'] = self.filter_id
        if self.paused:
            result['paused'] = self.paused
        return result


@dataclass
class FirewallRule:
    """Represents a Cloudflare Firewall rule"""
    rule_id: Optional[str] = None
    action: str = "block"
    description: str = ""
    filter_id: Optional[str] = None
    paused: bool = False
    priority: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'action': self.action,
            'description': self.description
        }
        if self.rule_id:
            result['id'] = self.rule_id
        if self.filter_id:
            result['filter'] = {'id': self.filter_id}
        if self.paused:
            result['paused'] = self.paused
        if self.priority:
            result['priority'] = self.priority
        return result


class CloudflareWAFIntegration:
    """
    Integration with Cloudflare Web Application Firewall (WAF).
    
    Usage:
        # Initialize
        cf = CloudflareWAFIntegration(
            api_token="your-api-token",
            account_id="your-account-id",
            zone_id="your-zone-id"
        )
        
        # Create AI threat detection rule
        rule_id = cf.create_ai_threat_rule(
            description="Block AI adversarial attacks",
            action="block"
        )
        
        # Block an IP
        cf.block_ip("192.168.1.100", "AI threat detected")
    """
    
    def __init__(
        self,
        api_token: str,
        account_id: str,
        zone_id: Optional[str] = None,
        api_url: str = "https://api.cloudflare.com/client/v4",
        timeout: int = 30
    ):
        """
        Initialize Cloudflare WAF integration.
        
        Args:
            api_token: Cloudflare API token
            account_id: Cloudflare account ID
            zone_id: Cloudflare zone ID (optional for zone-specific operations)
            api_url: Cloudflare API URL
            timeout: Request timeout in seconds
        """
        self.config = CloudflareConfig(
            api_token=api_token,
            account_id=account_id,
            zone_id=zone_id,
            api_url=api_url,
            timeout=timeout
        )
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        })
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        zone_required: bool = False
    ) -> Dict[str, Any]:
        """Make HTTP request to Cloudflare API"""
        if zone_required and not self.config.zone_id:
            return {'success': False, 'errors': [{'message': 'Zone ID is required for this operation'}]}
        
        url = f"{self.config.api_url}/{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.config.timeout
            )
            
            result = response.json()
            
            if not result.get('success', False):
                logger.error(f"Cloudflare API error: {result.get('errors')}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Cloudflare API request failed: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}
    
    def create_ai_threat_filter(self, description: str = "AI Adversarial Attack Detection") -> Optional[str]:
        """
        Create a WAF filter for AI threat detection.
        
        This filter matches requests containing AI adversarial patterns.
        
        Args:
            description: Filter description
        
        Returns:
            Filter ID or None if failed
        """
        # Expression to detect AI adversarial patterns
        # Matches common prompt injection and jailbreak attempts
        expression = (
            "(http.request.uri.query contains \"ignore\" and http.request.uri.query contains \"instructions\") or "
            "(http.request.uri.query contains \"DAN\" or http.request.uri.query contains \"jailbreak\") or "
            "(http.request.uri.query contains \"system prompt\" or http.request.uri.query contains \"extract data\") or "
            "(http.request.body.raw contains \"ignore\" and http.request.body.raw contains \"instructions\") or "
            "(http.request.body.raw contains \"DAN\" or http.request.body.raw contains \"jailbreak\") or "
            "(http.request.body.raw contains \"system prompt\" or http.request.body.raw contains \"extract data\")"
        )
        
        data = {
            'expression': expression,
            'description': description,
            'paused': False
        }
        
        result = self._make_request(
            'POST',
            f'accounts/{self.config.account_id}/rules/filters',
            data=data
        )
        
        if result.get('success'):
            return result['result']['id']
        return None
    
    def create_ai_threat_rule(
        self,
        filter_id: Optional[str] = None,
        description: str = "Block AI Adversarial Attacks",
        action: str = "block",
        priority: Optional[int] = None
    ) -> Optional[str]:
        """
        Create a WAF rule to block AI adversarial attacks.
        
        Args:
            filter_id: Filter ID to use (creates one if None)
            description: Rule description
            action: Action to take (block, challenge, allow, log)
            priority: Rule priority
        
        Returns:
            Rule ID or None if failed
        """
        if not filter_id:
            filter_id = self.create_ai_threat_filter(description)
            if not filter_id:
                return None
        
        data = {
            'action': action,
            'filter': {'id': filter_id},
            'description': description
        }
        
        if priority:
            data['priority'] = priority
        
        result = self._make_request(
            'POST',
            f'accounts/{self.config.account_id}/rules',
            data=data
        )
        
        if result.get('success'):
            return result['result']['id']
        return None
    
    def block_ip(self, ip_address: str, description: str = "AI threat detected") -> bool:
        """
        Block an IP address using Cloudflare Firewall.
        
        Args:
            ip_address: IP address to block
            description: Reason for blocking
        
        Returns:
            True if successful
        """
        if not self.config.zone_id:
            logger.error("Zone ID is required to block IPs")
            return False
        
        data = {
            'mode': 'block',
            'configuration': {
                'target': 'ip',
                'value': ip_address
            },
            'notes': description
        }
        
        result = self._make_request(
            'POST',
            f'zones/{self.config.zone_id}/firewall/rules',
            data=data,
            zone_required=True
        )
        
        return result.get('success', False)
    
    def challenge_ip(self, ip_address: str, description: str = "Suspicious activity") -> bool:
        """
        Challenge an IP address (CAPTCHA).
        
        Args:
            ip_address: IP address to challenge
            description: Reason for challenging
        
        Returns:
            True if successful
        """
        if not self.config.zone_id:
            return False
        
        data = {
            'mode': 'challenge',
            'configuration': {
                'target': 'ip',
                'value': ip_address
            },
            'notes': description
        }
        
        result = self._make_request(
            'POST',
            f'zones/{self.config.zone_id}/firewall/rules',
            data=data,
            zone_required=True
        )
        
        return result.get('success', False)
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Remove IP block.
        
        Args:
            ip_address: IP address to unblock
        
        Returns:
            True if successful
        """
        if not self.config.zone_id:
            return False
        
        # List all firewall rules and find the one with this IP
        result = self._make_request(
            'GET',
            f'zones/{self.config.zone_id}/firewall/rules',
            zone_required=True
        )
        
        if not result.get('success'):
            return False
        
        for rule in result['result']:
            if (rule.get('filter', {}).get('expression') == f'(ip.src eq {ip_address})' or
                rule.get('configuration', {}).get('value') == ip_address):
                delete_result = self._make_request(
                    'DELETE',
                    f'zones/{self.config.zone_id}/firewall/rules/{rule["id"]}',
                    zone_required=True
                )
                return delete_result.get('success', False)
        
        return False
    
    def create_rate_limit_rule(
        self,
        rate: int = 10,
        period: int = 10,
        action: str = "block",
        description: str = "Rate limit for AI API"
    ) -> Optional[str]:
        """
        Create a rate limiting rule.
        
        Args:
            rate: Number of requests allowed
            period: Time period in seconds
            action: Action to take when rate exceeded
            description: Rule description
        
        Returns:
            Rule ID or None if failed
        """
        if not self.config.zone_id:
            return None
        
        data = {
            'action': action,
            'rate': rate,
            'period': period,
            'description': description,
            'paused': False
        }
        
        result = self._make_request(
            'POST',
            f'zones/{self.config.zone_id}/rate_limits',
            data=data,
            zone_required=True
        )
        
        if result.get('success'):
            return result['result']['id']
        return None
    
    def create_custom_rule(
        self,
        expression: str,
        action: str = "block",
        description: str = "Custom WAF rule"
    ) -> Optional[str]:
        """
        Create a custom WAF rule.
        
        Args:
            expression: Firewall rule expression
            action: Action to take
            description: Rule description
        
        Returns:
            Rule ID or None if failed
        """
        if not self.config.zone_id:
            return None
        
        data = {
            'action': action,
            'expression': expression,
            'description': description,
            'paused': False
        }
        
        result = self._make_request(
            'POST',
            f'zones/{self.config.zone_id}/firewall/rules',
            data=data,
            zone_required=True
        )
        
        if result.get('success'):
            return result['result']['id']
        return None
    
    def list_waf_rules(self) -> List[Dict[str, Any]]:
        """List all WAF rules for the account"""
        result = self._make_request(
            'GET',
            f'accounts/{self.config.account_id}/rules'
        )
        
        if result.get('success'):
            return result.get('result', [])
        return []
    
    def list_firewall_rules(self) -> List[Dict[str, Any]]:
        """List all firewall rules for the zone"""
        if not self.config.zone_id:
            return []
        
        result = self._make_request(
            'GET',
            f'zones/{self.config.zone_id}/firewall/rules',
            zone_required=True
        )
        
        if result.get('success'):
            return result.get('result', [])
        return []
    
    def get_rule(self, rule_id: str, rule_type: str = "waf") -> Optional[Dict[str, Any]]:
        """
        Get a specific rule.
        
        Args:
            rule_id: Rule ID
            rule_type: Type of rule (waf, firewall)
        
        Returns:
            Rule data or None
        """
        if rule_type == "waf":
            result = self._make_request(
                'GET',
                f'accounts/{self.config.account_id}/rules/{rule_id}'
            )
        else:
            if not self.config.zone_id:
                return None
            result = self._make_request(
                'GET',
                f'zones/{self.config.zone_id}/firewall/rules/{rule_id}',
                zone_required=True
            )
        
        if result.get('success'):
            return result.get('result')
        return None
    
    def update_rule(
        self,
        rule_id: str,
        action: Optional[str] = None,
        description: Optional[str] = None,
        paused: Optional[bool] = None,
        rule_type: str = "waf"
    ) -> bool:
        """
        Update a WAF or firewall rule.
        
        Args:
            rule_id: Rule ID
            action: New action
            description: New description
            paused: Whether to pause the rule
            rule_type: Type of rule (waf, firewall)
        
        Returns:
            True if successful
        """
        data = {}
        if action:
            data['action'] = action
        if description:
            data['description'] = description
        if paused is not None:
            data['paused'] = paused
        
        if not data:
            return False
        
        if rule_type == "waf":
            result = self._make_request(
                'PATCH',
                f'accounts/{self.config.account_id}/rules/{rule_id}',
                data=data
            )
        else:
            if not self.config.zone_id:
                return False
            result = self._make_request(
                'PATCH',
                f'zones/{self.config.zone_id}/firewall/rules/{rule_id}',
                data=data,
                zone_required=True
            )
        
        return result.get('success', False)
    
    def delete_rule(self, rule_id: str, rule_type: str = "waf") -> bool:
        """
        Delete a WAF or firewall rule.
        
        Args:
            rule_id: Rule ID
            rule_type: Type of rule (waf, firewall)
        
        Returns:
            True if successful
        """
        if rule_type == "waf":
            result = self._make_request(
                'DELETE',
                f'accounts/{self.config.account_id}/rules/{rule_id}'
            )
        else:
            if not self.config.zone_id:
                return False
            result = self._make_request(
                'DELETE',
                f'zones/{self.config.zone_id}/firewall/rules/{rule_id}',
                zone_required=True
            )
        
        return result.get('success', False)
    
    def get_threat_analytics(self, start_time: Optional[str] = None, end_time: Optional[str] = None) -> Dict[str, Any]:
        """
        Get threat analytics from Cloudflare.
        
        Args:
            start_time: Start time in ISO format
            end_time: End time in ISO format
        
        Returns:
            Analytics data
        """
        if not self.config.zone_id:
            return {}
        
        params = {}
        if start_time:
            params['since'] = start_time
        if end_time:
            params['until'] = end_time
        
        result = self._make_request(
            'GET',
            f'zones/{self.config.zone_id}/analytics/threats',
            params=params,
            zone_required=True
        )
        
        if result.get('success'):
            return result.get('result', {})
        return {}
    
    def get_firewall_events(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get firewall events.
        
        Args:
            start_time: Start time in ISO format
            end_time: End time in ISO format
            limit: Maximum number of events
        
        Returns:
            List of firewall events
        """
        if not self.config.zone_id:
            return []
        
        params = {'limit': limit}
        if start_time:
            params['since'] = start_time
        if end_time:
            params['until'] = end_time
        
        result = self._make_request(
            'GET',
            f'zones/{self.config.zone_id}/firewall/events',
            params=params,
            zone_required=True
        )
        
        if result.get('success'):
            return result.get('result', [])
        return []
    
    def create_ai_defense_setup(self) -> Dict[str, Any]:
        """
        Create a complete AI defense setup in Cloudflare.
        
        Creates:
        1. AI threat detection filter
        2. AI threat blocking rule
        3. Rate limiting rule
        
        Returns:
            Dictionary with created rule IDs
        """
        results = {
            'ai_threat_filter': None,
            'ai_threat_rule': None,
            'rate_limit_rule': None
        }
        
        # Create AI threat filter
        filter_id = self.create_ai_threat_filter("AI Adversarial Attack Detection")
        if filter_id:
            results['ai_threat_filter'] = filter_id
            
            # Create AI threat rule
            rule_id = self.create_ai_threat_rule(
                filter_id=filter_id,
                description="Block AI Adversarial Attacks",
                action="block",
                priority=1
            )
            if rule_id:
                results['ai_threat_rule'] = rule_id
        
        # Create rate limit rule
        if self.config.zone_id:
            rate_rule_id = self.create_rate_limit_rule(
                rate=100,
                period=60,
                action="block",
                description="Rate limit for AI API"
            )
            if rate_rule_id:
                results['rate_limit_rule'] = rate_rule_id
        
        return results


# Convenience function
def create_cloudflare_waf(
    api_token: str,
    account_id: str,
    zone_id: Optional[str] = None
) -> CloudflareWAFIntegration:
    """Create a configured Cloudflare WAF integration"""
    return CloudflareWAFIntegration(
        api_token=api_token,
        account_id=account_id,
        zone_id=zone_id
    )
