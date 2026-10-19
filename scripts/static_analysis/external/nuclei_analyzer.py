"""
Nuclei Analyzer for Security Advisor Auditor v3.0
Integrates with Nuclei for vulnerability scanning.

Nuclei is a fast and customisable vulnerability scanner that can be used to
scan for a wide range of vulnerabilities using templates.
"""

import subprocess
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile
import os

from ..base_analyzer import BaseAnalyzer, Finding, ScanResult


class NucleiAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses Nuclei for vulnerability scanning.
    Nuclei uses templates to scan for known vulnerabilities.
    """
    
    TOOL_NAME = "nuclei"
    SUPPORTED_LANGUAGES = ["all"]  # Nuclei scans for vulnerabilities, not language-specific
    
    # Default template directories
    DEFAULT_TEMPLATES = [
        "~/.nuclei/templates/",
        "/usr/local/nuclei/templates/",
        "/opt/nuclei/templates/",
    ]
    
    # Template categories
    TEMPLATE_CATEGORIES = [
        "vulnerabilities",
        "exposures",
        "misconfigurations",
        "information-disclosure",
        "injection",
        "xss",
        "sqli",
        "rce",
        "ssrf",
        "idor",
        "lfi",
        "rfi",
        "xxe",
        "csrf",
        "cve",
    ]
    
    def __init__(self, templates_dir: str = None, update_templates: bool = False):
        """
        Initialize NucleiAnalyzer.
        
        Args:
            templates_dir: Custom templates directory
            update_templates: Whether to update templates on init
        """
        super().__init__()
        self.templates_dir = templates_dir or self._find_templates_dir()
        self._available = self._check_nuclei_installed()
        
        if update_templates and self.is_available():
            self.update_templates()
    
    def _check_nuclei_installed(self) -> bool:
        """Check if nuclei is installed and accessible."""
        try:
            result = subprocess.run(
                ['nuclei', '-version'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _find_templates_dir(self) -> Optional[str]:
        """Find the Nuclei templates directory."""
        for default_dir in self.DEFAULT_TEMPLATES:
            if Path(default_dir).exists():
                return default_dir
        
        # Try to find via nuclei command
        try:
            result = subprocess.run(
                ['nuclei', '-templates-path'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def is_available(self) -> bool:
        """Check if nuclei is available."""
        return self._available and self.templates_dir is not None
    
    def update_templates(self) -> bool:
        """Update Nuclei templates."""
        if not self.is_available():
            return False
        
        try:
            result = subprocess.run(
                ['nuclei', '-update-templates'],
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.returncode == 0
        except:
            return False
    
    def analyze_file(self, file_path: Union[str, Path], language: str = None) -> ScanResult:
        """
        Analyze a single file with Nuclei (not typically used for files).
        
        Note: Nuclei is designed for scanning URLs, not files. This method
        is provided for consistency but may not be useful.
        
        Args:
            file_path: Path to the file
            language: Language (ignored)
        
        Returns:
            ScanResult with findings
        """
        return ScanResult(
            target=str(file_path),
            tool=self.TOOL_NAME,
            language=language or "",
            findings=[],
            errors=["Nuclei is designed for URL scanning, not file analysis"],
            success=False
        )
    
    def analyze_code(self, code: str, language: str, file_path: str = "<stdin>") -> ScanResult:
        """
        Analyze code with Nuclei (not typically used).
        
        Args:
            code: Source code (ignored)
            language: Language (ignored)
            file_path: File path (ignored)
        
        Returns:
            ScanResult with findings
        """
        return ScanResult(
            target=file_path,
            tool=self.TOOL_NAME,
            language=language,
            findings=[],
            errors=["Nuclei is designed for URL scanning, not code analysis"],
            success=False
        )
    
    def scan_url(
        self,
        url: str,
        templates: List[str] = None,
        categories: List[str] = None,
        severity: List[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Scan a URL with Nuclei.
        
        Args:
            url: URL to scan
            templates: Specific templates to use
            categories: Template categories to use
            severity: Severity levels to include (info, low, medium, high, critical)
            **kwargs: Additional Nuclei options
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=url,
                tool=self.TOOL_NAME,
                language="",
                findings=[],
                errors=["Nuclei is not installed or templates not found"],
                success=False
            )
        
        # Build command
        cmd = ['nuclei']
        
        # Target
        cmd.append('-u')
        cmd.append(url)
        
        # Templates
        if templates:
            for template in templates:
                cmd.extend(['-t', template])
        elif categories:
            for category in categories:
                cmd.extend(['-t', f'{category}/'])
        else:
            # Use all templates by default
            cmd.extend(['-t', self.templates_dir])
        
        # Severity filter
        if severity:
            sev_map = {
                'info': 'i',
                'low': 'l',
                'medium': 'm',
                'high': 'h',
                'critical': 'c',
            }
            sev_str = ''.join([sev_map.get(s.lower(), '') for s in severity])
            if sev_str:
                cmd.extend(['-severity', sev_str])
        
        # Output format
        cmd.extend(['-json'])
        
        # Additional options
        if kwargs.get('rate_limit', None):
            cmd.extend(['-rate-limit', str(kwargs['rate_limit'])])
        if kwargs.get('threads', None):
            cmd.extend(['-threads', str(kwargs['threads'])])
        if kwargs.get('timeout', None):
            cmd.extend(['-timeout', str(kwargs['timeout'])])
        if kwargs.get('silent', False):
            cmd.append('-silent')
        if kwargs.get('no_color', False):
            cmd.append('-no-color')
        
        # Execute
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.get('timeout', 300)  # 5 minutes default
            )
            
            if result.returncode != 0:
                return ScanResult(
                    target=url,
                    tool=self.TOOL_NAME,
                    language="",
                    findings=[],
                    errors=[result.stderr],
                    success=False
                )
            
            # Parse output
            findings = self._parse_output(result.stdout)
            
            return ScanResult(
                target=url,
                tool=self.TOOL_NAME,
                language="",
                findings=findings,
                statistics={
                    'by_severity': self._count_by_severity(findings),
                    'by_category': self._count_by_category(findings),
                },
                success=True
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                target=url,
                tool=self.TOOL_NAME,
                language="",
                findings=[],
                errors=["Nuclei scan timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=url,
                tool=self.TOOL_NAME,
                language="",
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def scan_targets(
        self,
        targets: List[str],
        templates: List[str] = None,
        categories: List[str] = None,
        **kwargs
    ) -> Dict[str, ScanResult]:
        """
        Scan multiple targets with Nuclei.
        
        Args:
            targets: List of URLs to scan
            templates: Specific templates to use
            categories: Template categories to use
            **kwargs: Additional options
        
        Returns:
            Dictionary mapping target to ScanResult
        """
        results = {}
        for target in targets:
            results[target] = self.scan_url(
                target,
                templates=templates,
                categories=categories,
                **kwargs
            )
        return results
    
    def list_templates(self, category: str = None) -> List[Dict]:
        """
        List available Nuclei templates.
        
        Args:
            category: Filter by category
        
        Returns:
            List of template information
        """
        if not self.is_available() or not self.templates_dir:
            return []
        
        templates_dir = Path(self.templates_dir)
        templates = []
        
        for template_path in templates_dir.rglob('*.yaml'):
            try:
                with open(template_path, 'r') as f:
                    template_data = yaml.safe_load(f)
                
                if category:
                    if template_data.get('info', {}).get('category') == category:
                        templates.append({
                            'path': str(template_path),
                            'id': template_data.get('id', ''),
                            'name': template_data.get('info', {}).get('name', ''),
                            'category': template_data.get('info', {}).get('category', ''),
                            'severity': template_data.get('info', {}).get('severity', ''),
                            'description': template_data.get('info', {}).get('description', ''),
                        })
                else:
                    templates.append({
                        'path': str(template_path),
                        'id': template_data.get('id', ''),
                        'name': template_data.get('info', {}).get('name', ''),
                        'category': template_data.get('info', {}).get('category', ''),
                        'severity': template_data.get('info', {}).get('severity', ''),
                        'description': template_data.get('info', {}).get('description', ''),
                    })
            except:
                continue
        
        return templates
    
    def _parse_output(self, output: str) -> List[Finding]:
        """Parse Nuclei JSON output into Finding objects."""
        findings = []
        
        try:
            # Nuclei outputs one JSON object per line
            lines = output.strip().split('\n')
            for line in lines:
                if not line.strip():
                    continue
                    
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                # Extract template information
                template = data.get('template', {})
                info = data.get('info', {})
                
                finding = Finding(
                    tool=self.TOOL_NAME,
                    language="",
                    severity=self.SEVERITY_MAP.get(info.get('severity', 'medium').lower(), 'medium'),
                    confidence='high',  # Nuclei findings are typically high confidence
                    type='vulnerability',
                    category=template.get('id', info.get('name', '')),
                    title=info.get('name', template.get('id', 'Unknown Vulnerability')),
                    message=info.get('description', ''),
                    description=info.get('description', ''),
                    file=data.get('host', ''),
                    line=None,
                    column=None,
                    code='',
                    evidence=data.get('extracted', ''),
                    proof_of_concept=data.get('curl-command', ''),
                    remediation=info.get('remediation', ''),
                    fix='',
                    references=template.get('references', []),
                    tags=template.get('tags', []),
                    cvss_score=info.get('cvss_score'),
                    cvss_vector=info.get('cvss_vector', ''),
                )
                
                findings.append(finding)
        except Exception as e:
            # Log error but continue
            pass
        
        return findings
