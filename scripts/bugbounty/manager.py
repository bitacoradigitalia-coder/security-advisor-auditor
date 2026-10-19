"""
Bug Bounty Manager for Security Advisor Auditor v3.0
Manages Bug Bounty programs, findings, and report generation.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import uuid


@dataclass
class BugBountyProgram:
    """Represents a Bug Bounty program."""
    name: str
    scope: List[str] = field(default_factory=list)
    rules: str = ""
    platform: str = "generic"  # hackerone, bugcrowd, intigriti, other
    platform_handle: str = ""
    api_token: str = ""
    severity_system: str = "CVSS"  # CVSS, custom, etc.
    reward_range: Dict[str, int] = field(default_factory=dict)
    in_scope_assets: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    eligible_vulnerabilities: List[str] = field(default_factory=list)
    ineligible_vulnerabilities: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    active: bool = True
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'scope': self.scope,
            'rules': self.rules,
            'platform': self.platform,
            'platform_handle': self.platform_handle,
            'api_token': self.api_token,
            'severity_system': self.severity_system,
            'reward_range': self.reward_range,
            'in_scope_assets': self.in_scope_assets,
            'out_of_scope_assets': self.out_of_scope_assets,
            'eligible_vulnerabilities': self.eligible_vulnerabilities,
            'ineligible_vulnerabilities': self.ineligible_vulnerabilities,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'active': self.active,
            'notes': self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BugBountyProgram':
        return cls(
            name=data.get('name', ''),
            scope=data.get('scope', []),
            rules=data.get('rules', ''),
            platform=data.get('platform', 'generic'),
            platform_handle=data.get('platform_handle', ''),
            api_token=data.get('api_token', ''),
            severity_system=data.get('severity_system', 'CVSS'),
            reward_range=data.get('reward_range', {}),
            in_scope_assets=data.get('in_scope_assets', []),
            out_of_scope_assets=data.get('out_of_scope_assets', []),
            eligible_vulnerabilities=data.get('eligible_vulnerabilities', []),
            ineligible_vulnerabilities=data.get('ineligible_vulnerabilities', []),
            created_at=data.get('created_at', datetime.now().isoformat()),
            updated_at=data.get('updated_at', datetime.now().isoformat()),
            active=data.get('active', True),
            notes=data.get('notes', '')
        )
    
    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is in scope for this program.
        
        Args:
            target: Target URL or domain
        
        Returns:
            True if target is in scope
        """
        for scope_item in self.scope:
            if self._matches_scope(target, scope_item):
                return True
        
        for asset in self.in_scope_assets:
            if self._matches_scope(target, asset):
                return True
        
        return False
    
    def _matches_scope(self, target: str, scope: str) -> bool:
        """
        Check if target matches a scope pattern.
        
        Args:
            target: Target URL
            scope: Scope pattern
        
        Returns:
            True if target matches scope
        """
        # Handle wildcard patterns
        if '*' in scope:
            # Convert to regex
            pattern = scope.replace('*', '.*')
            pattern = f'^{pattern}$'
            return bool(re.match(pattern, target, re.IGNORECASE))
        
        # Handle domain matching
        target_domain = self._extract_domain(target)
        scope_domain = self._extract_domain(scope)
        
        return target_domain == scope_domain or target_domain.endswith('.' + scope_domain)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        # Remove protocol
        domain = url.replace('https://', '').replace('http://', '').replace('www.', '')
        # Remove path and query
        domain = domain.split('/')[0].split('?')[0].split('#')[0]
        # Remove port
        domain = domain.split(':')[0]
        return domain.lower()


@dataclass
class BugBountyFinding:
    """Represents a Bug Bounty finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: str = "medium"  # info, low, medium, high, critical
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    vulnerability_type: str = ""
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    payload: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    impact: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    program: str = ""
    status: str = "new"  # new, triaged, submitted, accepted, rejected, duplicate, out_of_scope
    state: str = "open"  # open, closed, fixed, won't fix
    priority: str = "medium"  # low, medium, high, critical
    confidence: str = "medium"  # low, medium, high, confirmed
    
    # Timestamps
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    submitted_at: Optional[str] = None
    accepted_at: Optional[str] = None
    closed_at: Optional[str] = None
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Platform-specific
    platform_id: Optional[str] = None
    platform_url: Optional[str] = None
    platform_status: Optional[str] = None
    
    # Rewards
    reward: Optional[int] = None
    reward_currency: str = "USD"
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'vulnerability_type': self.vulnerability_type,
            'target': self.target,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'steps_to_reproduce': self.steps_to_reproduce,
            'impact': self.impact,
            'proof_of_concept': self.proof_of_concept,
            'remediation': self.remediation,
            'references': self.references,
            'program': self.program,
            'status': self.status,
            'state': self.state,
            'priority': self.priority,
            'confidence': self.confidence,
            'discovered_at': self.discovered_at,
            'submitted_at': self.submitted_at,
            'accepted_at': self.accepted_at,
            'closed_at': self.closed_at,
            'updated_at': self.updated_at,
            'platform_id': self.platform_id,
            'platform_url': self.platform_url,
            'platform_status': self.platform_status,
            'reward': self.reward,
            'reward_currency': self.reward_currency,
            'tags': self.tags,
            'attachments': self.attachments,
            'notes': self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BugBountyFinding':
        return cls(
            id=data.get('id', str(uuid.uuid4())),
            title=data.get('title', ''),
            description=data.get('description', ''),
            severity=data.get('severity', 'medium'),
            cvss_score=data.get('cvss_score'),
            cvss_vector=data.get('cvss_vector', ''),
            vulnerability_type=data.get('vulnerability_type', ''),
            target=data.get('target', ''),
            endpoint=data.get('endpoint', ''),
            parameter=data.get('parameter', ''),
            payload=data.get('payload', ''),
            steps_to_reproduce=data.get('steps_to_reproduce', []),
            impact=data.get('impact', ''),
            proof_of_concept=data.get('proof_of_concept', ''),
            remediation=data.get('remediation', ''),
            references=data.get('references', []),
            program=data.get('program', ''),
            status=data.get('status', 'new'),
            state=data.get('state', 'open'),
            priority=data.get('priority', 'medium'),
            confidence=data.get('confidence', 'medium'),
            discovered_at=data.get('discovered_at', datetime.now().isoformat()),
            submitted_at=data.get('submitted_at'),
            accepted_at=data.get('accepted_at'),
            closed_at=data.get('closed_at'),
            updated_at=data.get('updated_at', datetime.now().isoformat()),
            platform_id=data.get('platform_id'),
            platform_url=data.get('platform_url'),
            platform_status=data.get('platform_status'),
            reward=data.get('reward'),
            reward_currency=data.get('reward_currency', 'USD'),
            tags=data.get('tags', []),
            attachments=data.get('attachments', []),
            notes=data.get('notes', '')
        )
    
    def get_severity_emoji(self) -> str:
        """Get emoji for severity level."""
        severities = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵'
        }
        return severities.get(self.severity.lower(), '⚪')
    
    def get_status_emoji(self) -> str:
        """Get emoji for status."""
        statuses = {
            'new': '🆕',
            'triaged': '🔍',
            'submitted': '📤',
            'accepted': '✅',
            'rejected': '❌',
            'duplicate': '🔄',
            'out_of_scope': '🚫'
        }
        return statuses.get(self.status.lower(), '❓')


class BugBountyManager:
    """
    Manages Bug Bounty programs and findings.
    Provides functionality to add, update, and track Bug Bounty submissions.
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize BugBountyManager.
        
        Args:
            storage_path: Path to storage file
        """
        self.storage_path = storage_path or os.path.join(os.path.expanduser('~'), '.security_advisor', 'bugbounty.json')
        self._programs: Dict[str, BugBountyProgram] = {}
        self._findings: Dict[str, BugBountyFinding] = {}
        
        # Load existing data
        self._load_data()
    
    def _load_data(self) -> None:
        """Load programs and findings from storage."""
        if not os.path.exists(self.storage_path):
            return
        
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                for name, program_data in data.get('programs', {}).items():
                    self._programs[name] = BugBountyProgram.from_dict(program_data)
                
                for finding_id, finding_data in data.get('findings', {}).items():
                    finding = BugBountyFinding.from_dict(finding_data)
                    self._findings[finding_id] = finding
        except (json.JSONDecodeError, IOError):
            self._programs = {}
            self._findings = {}
    
    def _save_data(self) -> None:
        """Save programs and findings to storage."""
        data = {
            'programs': {name: program.to_dict() for name, program in self._programs.items()},
            'findings': {finding_id: finding.to_dict() for finding_id, finding in self._findings.items()}
        }
        
        # Create directory if it doesn't exist
        Path(self.storage_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Write with restricted permissions
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Set file permissions (readable only by owner)
        try:
            os.chmod(self.storage_path, 0o600)
        except (OSError, AttributeError):
            pass
    
    # ========================================================================
    # Program Management
    # ========================================================================
    
    def add_program(
        self,
        name: str,
        scope: Union[str, List[str]],
        rules: str = "",
        platform: str = "generic",
        platform_handle: str = "",
        api_token: str = "",
        **kwargs
    ) -> BugBountyProgram:
        """
        Add a new Bug Bounty program.
        
        Args:
            name: Program name
            scope: Scope (string or list of strings)
            rules: Program rules
            platform: Platform (hackerone, bugcrowd, intigriti, other)
            platform_handle: Platform handle/username
            api_token: API token for platform integration
            **kwargs: Additional program properties
        
        Returns:
            The created BugBountyProgram
        """
        if isinstance(scope, str):
            scope = [s.strip() for s in scope.split(',')]
        
        program = BugBountyProgram(
            name=name,
            scope=scope,
            rules=rules,
            platform=platform,
            platform_handle=platform_handle,
            api_token=api_token,
            **kwargs
        )
        
        self._programs[name] = program
        self._save_data()
        
        return program
    
    def update_program(self, name: str, **kwargs) -> bool:
        """
        Update an existing Bug Bounty program.
        
        Args:
            name: Program name
            **kwargs: Properties to update
        
        Returns:
            True if program was updated, False otherwise
        """
        if name not in self._programs:
            return False
        
        program = self._programs[name]
        for key, value in kwargs.items():
            if hasattr(program, key):
                setattr(program, key, value)
        
        program.updated_at = datetime.now().isoformat()
        self._save_data()
        return True
    
    def get_program(self, name: str) -> Optional[BugBountyProgram]:
        """
        Get a Bug Bounty program by name.
        
        Args:
            name: Program name
        
        Returns:
            BugBountyProgram or None if not found
        """
        return self._programs.get(name)
    
    def remove_program(self, name: str) -> bool:
        """
        Remove a Bug Bounty program.
        
        Args:
            name: Program name
        
        Returns:
            True if program was removed, False otherwise
        """
        if name in self._programs:
            del self._programs[name]
            self._save_data()
            return True
        return False
    
    def list_programs(self) -> List[str]:
        """
        List all Bug Bounty programs.
        
        Returns:
            List of program names
        """
        return list(self._programs.keys())
    
    # ========================================================================
    # Finding Management
    # ========================================================================
    
    def add_finding(
        self,
        program: str,
        finding: Dict[str, Any],
        **kwargs
    ) -> Optional[BugBountyFinding]:
        """
        Add a new finding to a Bug Bounty program.
        
        Args:
            program: Program name
            finding: Finding data (can be from scan results)
            **kwargs: Additional finding properties
        
        Returns:
            The created BugBountyFinding or None if program not found
        """
        # Get program
        program_obj = self._programs.get(program)
        if not program_obj:
            return None
        
        # Check if target is in scope
        target = finding.get('target', finding.get('location', {}).get('file', ''))
        if target and not program_obj.is_in_scope(target):
            # Still add it, but mark as out of scope
            kwargs['status'] = 'out_of_scope'
        
        # Create finding
        bb_finding = BugBountyFinding(
            program=program,
            **self._extract_finding_data(finding),
            **kwargs
        )
        
        # Generate ID if not provided
        if not bb_finding.id:
            bb_finding.id = str(uuid.uuid4())
        
        # Set timestamps
        bb_finding.discovered_at = bb_finding.discovered_at or datetime.now().isoformat()
        bb_finding.updated_at = datetime.now().isoformat()
        
        self._findings[bb_finding.id] = bb_finding
        self._save_data()
        
        return bb_finding
    
    def _extract_finding_data(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant data from a finding dictionary.
        
        Args:
            finding: Finding data from scan
        
        Returns:
            Dictionary with extracted data
        """
        data = {}
        
        # Extract basic info
        data['title'] = finding.get('title', finding.get('type', 'Untitled Finding'))
        data['description'] = finding.get('description', finding.get('details', {}).get('description', ''))
        data['severity'] = finding.get('severity', 'medium')
        data['vulnerability_type'] = finding.get('type', finding.get('vulnerability_type', 'unknown'))
        
        # Extract location info
        location = finding.get('location', {})
        if isinstance(location, dict):
            data['target'] = location.get('file', '')
            data['endpoint'] = location.get('endpoint', '')
            data['parameter'] = location.get('parameter', '')
        else:
            data['target'] = str(location)
        
        # Extract evidence
        evidence = finding.get('evidence', {})
        if isinstance(evidence, dict):
            data['payload'] = evidence.get('payload', '')
            data['proof_of_concept'] = evidence.get('summary', '')
        
        # Extract steps to reproduce
        if 'steps' in finding:
            data['steps_to_reproduce'] = finding['steps']
        elif 'reproduction' in finding:
            data['steps_to_reproduce'] = [finding['reproduction']]
        
        # Extract impact
        data['impact'] = finding.get('impact', finding.get('description', ''))
        
        # Extract remediation
        data['remediation'] = finding.get('remediation', '')
        
        # Extract references
        data['references'] = finding.get('references', [])
        
        # Extract CVSS
        data['cvss_score'] = finding.get('cvss_score')
        data['cvss_vector'] = finding.get('cvss_vector', '')
        
        # Extract tags
        data['tags'] = finding.get('tags', [])
        
        return data
    
    def update_finding(self, finding_id: str, **kwargs) -> bool:
        """
        Update an existing finding.
        
        Args:
            finding_id: Finding ID
            **kwargs: Properties to update
        
        Returns:
            True if finding was updated, False otherwise
        """
        if finding_id not in self._findings:
            return False
        
        finding = self._findings[finding_id]
        for key, value in kwargs.items():
            if hasattr(finding, key):
                setattr(finding, key, value)
        
        finding.updated_at = datetime.now().isoformat()
        self._save_data()
        return True
    
    def get_finding(self, finding_id: str) -> Optional[BugBountyFinding]:
        """
        Get a finding by ID.
        
        Args:
            finding_id: Finding ID
        
        Returns:
            BugBountyFinding or None if not found
        """
        return self._findings.get(finding_id)
    
    def remove_finding(self, finding_id: str) -> bool:
        """
        Remove a finding.
        
        Args:
            finding_id: Finding ID
        
        Returns:
            True if finding was removed, False otherwise
        """
        if finding_id in self._findings:
            del self._findings[finding_id]
            self._save_data()
            return True
        return False
    
    def list_findings(self, program: Optional[str] = None) -> List[BugBountyFinding]:
        """
        List findings for a specific program or all programs.
        
        Args:
            program: Program name (optional)
        
        Returns:
            List of BugBountyFinding objects
        """
        if program:
            return [f for f in self._findings.values() if f.program == program]
        return list(self._findings.values())
    
    def list_all_findings(self) -> List[BugBountyFinding]:
        """
        List all findings across all programs.
        
        Returns:
            List of BugBountyFinding objects
        """
        return list(self._findings.values())
    
    def get_findings_by_status(self, status: str) -> List[BugBountyFinding]:
        """
        Get findings by status.
        
        Args:
            status: Status to filter by
        
        Returns:
            List of BugBountyFinding objects
        """
        return [f for f in self._findings.values() if f.status.lower() == status.lower()]
    
    def get_findings_by_severity(self, severity: str) -> List[BugBountyFinding]:
        """
        Get findings by severity.
        
        Args:
            severity: Severity to filter by
        
        Returns:
            List of BugBountyFinding objects
        """
        return [f for f in self._findings.values() if f.severity.lower() == severity.lower()]
    
    # ========================================================================
    # Report Generation
    # ========================================================================
    
    def generate_report(
        self,
        finding_id: str,
        format: str = 'markdown',
        platform: str = 'generic'
    ) -> str:
        """
        Generate a report for a finding.
        
        Args:
            finding_id: Finding ID
            format: Output format (markdown, html, json)
            platform: Target platform (hackerone, bugcrowd, generic)
        
        Returns:
            Generated report as string
        """
        finding = self._findings.get(finding_id)
        if not finding:
            return f"# Error: Finding '{finding_id}' not found"
        
        program = self._programs.get(finding.program)
        
        if format == 'json':
            return json.dumps(finding.to_dict(), indent=2, ensure_ascii=False)
        
        elif format == 'html':
            return self._generate_html_report(finding, program)
        
        else:  # markdown (default)
            return self._generate_markdown_report(finding, program, platform)
    
    def _generate_markdown_report(
        self,
        finding: BugBountyFinding,
        program: Optional[BugBountyProgram],
        platform: str
    ) -> str:
        """Generate a Markdown report."""
        lines = []
        
        # Title
        lines.append(f"# {finding.title}")
        lines.append("")
        
        # Badges
        severity_emoji = finding.get_severity_emoji()
        status_emoji = finding.get_status_emoji()
        lines.append(f"{severity_emoji} **Severity:** {finding.severity.upper()}")
        lines.append(f"{status_emoji} **Status:** {finding.status.upper()}")
        if finding.cvss_score:
            lines.append(f"📊 **CVSS Score:** {finding.cvss_score}")
        if finding.cvss_vector:
            lines.append(f"🎯 **CVSS Vector:** {finding.cvss_vector}")
        lines.append("")
        
        # Program info
        if program:
            lines.append("## Program Information")
            lines.append("")
            lines.append(f"**Program:** {program.name}")
            lines.append(f"**Platform:** {program.platform.upper()}")
            if program.platform_handle:
                lines.append(f"**Handle:** {program.platform_handle}")
            lines.append("")
        
        # Vulnerability details
        lines.append("## Vulnerability Details")
        lines.append("")
        lines.append(f"**Type:** {finding.vulnerability_type.upper()}")
        lines.append(f"**Target:** {finding.target}")
        if finding.endpoint:
            lines.append(f"**Endpoint:** {finding.endpoint}")
        if finding.parameter:
            lines.append(f"**Parameter:** {finding.parameter}")
        if finding.payload:
            lines.append(f"**Payload:** `{finding.payload}`")
        lines.append("")
        
        # Description
        lines.append("## Description")
        lines.append("")
        lines.append(finding.description)
        lines.append("")
        
        # Steps to reproduce
        if finding.steps_to_reproduce:
            lines.append("## Steps to Reproduce")
            lines.append("")
            for i, step in enumerate(finding.steps_to_reproduce, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
        
        # Proof of Concept
        if finding.proof_of_concept:
            lines.append("## Proof of Concept")
            lines.append("")
            lines.append(f"```")
            lines.append(finding.proof_of_concept)
            lines.append(f"```")
            lines.append("")
        
        # Impact
        if finding.impact:
            lines.append("## Impact")
            lines.append("")
            lines.append(finding.impact)
            lines.append("")
        
        # Remediation
        if finding.remediation:
            lines.append("## Remediation")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")
        
        # References
        if finding.references:
            lines.append("## References")
            lines.append("")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")
        
        # Tags
        if finding.tags:
            lines.append("## Tags")
            lines.append("")
            lines.append(", ".join(finding.tags))
            lines.append("")
        
        # Metadata
        lines.append("---")
        lines.append("")
        lines.append("### Metadata")
        lines.append("")
        lines.append(f"**Finding ID:** {finding.id}")
        lines.append(f"**Discovered:** {finding.discovered_at}")
        if finding.submitted_at:
            lines.append(f"**Submitted:** {finding.submitted_at}")
        if finding.accepted_at:
            lines.append(f"**Accepted:** {finding.accepted_at}")
        if finding.closed_at:
            lines.append(f"**Closed:** {finding.closed_at}")
        lines.append(f"**Last Updated:** {finding.updated_at}")
        lines.append("")
        
        if finding.notes:
            lines.append("### Notes")
            lines.append("")
            lines.append(finding.notes)
        
        return "\n".join(lines)
    
    def _generate_html_report(
        self,
        finding: BugBountyFinding,
        program: Optional[BugBountyProgram]
    ) -> str:
        """Generate an HTML report."""
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        
        status_colors = {
            'new': '#007bff',
            'triaged': '#17a2b8',
            'submitted': '#6c757d',
            'accepted': '#28a745',
            'rejected': '#dc3545',
            'duplicate': '#6c757d',
            'out_of_scope': '#6c757d'
        }
        
        color = severity_colors.get(finding.severity.lower(), '#6c757d')
        status_color = status_colors.get(finding.status.lower(), '#6c757d')
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{finding.title} - Bug Bounty Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            border-bottom: 2px solid {color};
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: {color};
            margin-bottom: 10px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: bold;
            margin-right: 10px;
        }}
        .severity-badge {{
            background-color: {color};
            color: white;
        }}
        .status-badge {{
            background-color: {status_color};
            color: white;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .section h2 {{
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        .code-block {{
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
        }}
        .metadata dt {{
            font-weight: bold;
            color: #6c757d;
        }}
        .metadata dd {{
            margin-left: 0;
            margin-bottom: 10px;
        }}
        .tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .tag {{
            background-color: #e9ecef;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .reference-list li {{
            margin-bottom: 8px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{finding.title}</h1>
        <div>
            <span class="badge severity-badge">{finding.severity.upper()}</span>
            <span class="badge status-badge">{finding.status.upper()}</span>
            {'<span class="badge">CVSS: ' + str(finding.cvss_score) + '</span>' if finding.cvss_score else ''}
        </div>
    </div>
    
    {'<div class="section"><h2>Program Information</h2>' + 
     f'<dl class="metadata"><dt>Program</dt><dd>{program.name if program else finding.program}</dd>' + 
     f'<dt>Platform</dt><dd>{program.platform.upper() if program else "N/A"}</dd>' + 
     (f'<dt>Handle</dt><dd>{program.platform_handle}</dd>' if program and program.platform_handle else '') + 
     '</dl></div>' if program else ''}
    
    <div class="section">
        <h2>Vulnerability Details</h2>
        <dl class="metadata">
            <dt>Type</dt><dd>{finding.vulnerability_type.upper()}</dd>
            <dt>Target</dt><dd><code>{finding.target}</code></dd>
            {'<dt>Endpoint</dt><dd><code>' + finding.endpoint + '</code></dd>' if finding.endpoint else ''}
            {'<dt>Parameter</dt><dd><code>' + finding.parameter + '</code></dd>' if finding.parameter else ''}
            {'<dt>Payload</dt><dd><code>' + finding.payload + '</code></dd>' if finding.payload else ''}
        </dl>
    </div>
    
    <div class="section">
        <h2>Description</h2>
        <p>{finding.description}</p>
    </div>
    
    {'<div class="section"><h2>Steps to Reproduce</h2><ol>' + 
     ''.join(f'<li>{step}</li>' for step in finding.steps_to_reproduce) + 
     '</ol></div>' if finding.steps_to_reproduce else ''}
    
    {'<div class="section"><h2>Proof of Concept</h2><div class="code-block"><pre>' + 
     finding.proof_of_concept + '</pre></div></div>' if finding.proof_of_concept else ''}
    
    {'<div class="section"><h2>Impact</h2><p>' + finding.impact + '</p></div>' if finding.impact else ''}
    
    {'<div class="section"><h2>Remediation</h2><p>' + finding.remediation + '</p></div>' if finding.remediation else ''}
    
    {'<div class="section"><h2>References</h2><ul class="reference-list">' + 
     ''.join(f'<li>{ref}</li>' for ref in finding.references) + 
     '</ul></div>' if finding.references else ''}
    
    {'<div class="section"><h2>Tags</h2><div class="tags">' + 
     ''.join(f'<span class="tag">{tag}</span>' for tag in finding.tags) + 
     '</div></div>' if finding.tags else ''}
    
    <div class="section">
        <h2>Metadata</h2>
        <dl class="metadata">
            <dt>Finding ID</dt><dd>{finding.id}</dd>
            <dt>Discovered</dt><dd>{finding.discovered_at}</dd>
            {'<dt>Submitted</dt><dd>' + finding.submitted_at + '</dd>' if finding.submitted_at else ''}
            {'<dt>Accepted</dt><dd>' + finding.accepted_at + '</dd>' if finding.accepted_at else ''}
            {'<dt>Closed</dt><dd>' + finding.closed_at + '</dd>' if finding.closed_at else ''}
            <dt>Last Updated</dt><dd>{finding.updated_at}</dd>
        </dl>
    </div>
    
    {'<div class="section"><h2>Notes</h2><p>' + finding.notes + '</p></div>' if finding.notes else ''}
    
    <div class="section">
        <p><small>Generated by Security Advisor Auditor v3.0</small></p>
    </div>
</body>
</html>'''
        
        return html
    
    # ========================================================================
    # Statistics and Analytics
    # ========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about Bug Bounty programs and findings.
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_programs': len(self._programs),
            'total_findings': len(self._findings),
            'programs': {},
            'findings_by_severity': {},
            'findings_by_status': {},
            'findings_by_type': {},
            'rewards': {
                'total': 0,
                'by_program': {},
                'by_severity': {}
            }
        }
        
        # Program statistics
        for name, program in self._programs.items():
            program_findings = [f for f in self._findings.values() if f.program == name]
            stats['programs'][name] = {
                'findings': len(program_findings),
                'by_severity': {},
                'by_status': {},
                'rewards': 0
            }
            
            for finding in program_findings:
                # Count by severity
                severity = finding.severity.lower()
                stats['programs'][name]['by_severity'][severity] = \
                    stats['programs'][name]['by_severity'].get(severity, 0) + 1
                
                # Count by status
                status = finding.status.lower()
                stats['programs'][name]['by_status'][status] = \
                    stats['programs'][name]['by_status'].get(status, 0) + 1
                
                # Sum rewards
                if finding.reward:
                    stats['programs'][name]['rewards'] += finding.reward
        
        # Findings by severity
        for finding in self._findings.values():
            severity = finding.severity.lower()
            stats['findings_by_severity'][severity] = \
                stats['findings_by_severity'].get(severity, 0) + 1
        
        # Findings by status
        for finding in self._findings.values():
            status = finding.status.lower()
            stats['findings_by_status'][status] = \
                stats['findings_by_status'].get(status, 0) + 1
        
        # Findings by type
        for finding in self._findings.values():
            vtype = finding.vulnerability_type.lower()
            stats['findings_by_type'][vtype] = \
                stats['findings_by_type'].get(vtype, 0) + 1
        
        # Rewards
        for finding in self._findings.values():
            if finding.reward:
                stats['rewards']['total'] += finding.reward
                
                if finding.program:
                    stats['rewards']['by_program'][finding.program] = \
                        stats['rewards']['by_program'].get(finding.program, 0) + finding.reward
                
                severity = finding.severity.lower()
                stats['rewards']['by_severity'][severity] = \
                    stats['rewards']['by_severity'].get(severity, 0) + finding.reward
        
        return stats
    
    def get_leaderboard(self) -> List[Dict[str, Any]]:
        """
        Get a leaderboard of researchers based on findings.
        
        Returns:
            List of researcher statistics
        """
        # This would be populated with actual researcher data
        # For now, return empty list
        return []


# Global instance
_bugbounty_manager: Optional[BugBountyManager] = None


def get_bugbounty_manager(storage_path: Optional[str] = None) -> BugBountyManager:
    """
    Get or create the global BugBountyManager instance.
    
    Args:
        storage_path: Path to storage file
    
    Returns:
        BugBountyManager instance
    """
    global _bugbounty_manager
    if _bugbounty_manager is None:
        _bugbounty_manager = BugBountyManager(storage_path)
    return _bugbounty_manager


def reset_bugbounty_manager() -> None:
    """Reset the global BugBountyManager instance."""
    global _bugbounty_manager
    if _bugbounty_manager is not None:
        _bugbounty_manager._save_data()
    _bugbounty_manager = None
