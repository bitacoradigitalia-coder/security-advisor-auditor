"""
PHPStan Security Analyzer for Security Advisor Auditor v3.0
Integrates with PHPStan and php-security-scanner for PHP static analysis.
"""

import subprocess
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile
import os

from ..base_analyzer import BaseAnalyzer, Finding, ScanResult


class PHPStanAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses PHPStan for PHP static analysis.
    PHPStan focuses on finding bugs in PHP code.
    """
    
    TOOL_NAME = "phpstan-security"
    SUPPORTED_LANGUAGES = ["php"]
    
    # PHPStan levels (0-9, higher = stricter)
    DEFAULT_LEVEL = 5
    
    # Security-related error codes
    SECURITY_ERRORS = [
        'security',
        'sql-injection',
        'xss',
        'csrf',
        'path-traversal',
        'file-upload',
        'command-injection',
        'rce',
        'lfi',
        'rfi',
        'xxe',
        'ssrf',
        'idor',
        'hardcoded-password',
        'hardcoded-secret',
        'eval',
        'create_function',
        'unserialize',
        'extract',
        'parse_str',
        'mb_parse_str',
    ]
    
    def __init__(self, level: int = None):
        """
        Initialize PHPStanAnalyzer.
        
        Args:
            level: PHPStan level (0-9)
        """
        super().__init__()
        self.level = level or self.DEFAULT_LEVEL
        self._available = self._check_phpstan_installed()
    
    def _check_phpstan_installed(self) -> bool:
        """Check if phpstan is installed and accessible."""
        try:
            result = subprocess.run(
                ['phpstan', '--version'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def is_available(self) -> bool:
        """Check if phpstan is available."""
        return self._available
    
    def analyze_file(self, file_path: Union[str, Path], language: str = None) -> ScanResult:
        """
        Analyze a PHP file with PHPStan.
        
        Args:
            file_path: Path to the PHP file
            language: Language (ignored, always php)
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=["PHPStan is not installed"],
                success=False
            )
        
        file_path = Path(file_path)
        if not file_path.exists():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=[f"File not found: {file_path}"],
                success=False
            )
        
        # Build command
        cmd = ['phpstan']
        
        # Analysis level
        cmd.extend(['--level', str(self.level)])
        
        # Output format (JSON)
        cmd.extend(['--error-format', 'json'])
        
        # Target
        cmd.append(str(file_path))
        
        # Execute
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            # Parse output
            findings = self._parse_output(result.stdout)
            
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=findings,
                statistics={
                    'by_severity': self._count_by_severity(findings),
                    'by_category': self._count_by_category(findings),
                },
                success=result.returncode == 0
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=["PHPStan analysis timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def analyze_code(self, code: str, language: str = "php", file_path: str = "<stdin>") -> ScanResult:
        """
        Analyze PHP code directly with PHPStan.
        
        Args:
            code: PHP source code
            language: Language (ignored, always php)
            file_path: Virtual file path
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=file_path,
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=["PHPStan is not installed"],
                success=False
            )
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.php',
            delete=False
        ) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            result = self.analyze_file(temp_path, "php")
            return result
        finally:
            # Clean up
            try:
                os.unlink(temp_path)
            except:
                pass
    
    def analyze_directory(self, dir_path: Union[str, Path], languages: List[str] = None) -> ScanResult:
        """
        Analyze all PHP files in a directory with PHPStan.
        
        Args:
            dir_path: Path to the directory
            languages: Language filter (ignored, always php)
        
        Returns:
            ScanResult with all findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=["PHPStan is not installed"],
                success=False
            )
        
        dir_path = Path(dir_path)
        if not dir_path.exists():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=[f"Directory not found: {dir_path}"],
                success=False
            )
        
        # Build command
        cmd = ['phpstan']
        
        # Analysis level
        cmd.extend(['--level', str(self.level)])
        
        # Output format
        cmd.extend(['--error-format', 'json'])
        
        # Target directory
        cmd.append(str(dir_path))
        
        # Execute
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )
            
            # Parse output
            findings = self._parse_output(result.stdout)
            
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=findings,
                statistics={
                    'by_severity': self._count_by_severity(findings),
                    'by_category': self._count_by_category(findings),
                },
                success=result.returncode == 0
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=["PHPStan analysis timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="php",
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def _parse_output(self, output: str) -> List[Finding]:
        """Parse PHPStan JSON output into Finding objects."""
        findings = []
        
        try:
            # PHPStan outputs one JSON object per line
            lines = output.strip().split('\n')
            for line in lines:
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                # Extract error information
                file = data.get('file', '')
                line_number = data.get('line', None)
                column = data.get('column', None)
                message = data.get('message', '')
                severity = data.get('severity', 'error')
                identifier = data.get('identifier', '')
                
                # Check if this is a security-related error
                is_security = any(
                    error in identifier.lower() or error in message.lower()
                    for error in self.SECURITY_ERRORS
                )
                
                if not is_security:
                    continue
                
                # Map PHPStan severity to ours
                if severity == 'error':
                    finding_severity = 'high'
                elif severity == 'warning':
                    finding_severity = 'medium'
                else:
                    finding_severity = 'low'
                
                # Get rule information
                rule_info = self._get_rule_info(identifier)
                
                finding = Finding(
                    tool=self.TOOL_NAME,
                    language="php",
                    severity=finding_severity,
                    confidence='high' if severity == 'error' else 'medium',
                    type='vulnerability' if finding_severity in ['high', 'critical'] else 'risk',
                    category=identifier,
                    title=rule_info.get('title', identifier),
                    message=message,
                    description=rule_info.get('description', message),
                    file=file,
                    line=line_number,
                    column=column,
                    code='',
                    evidence='',
                    proof_of_concept='',
                    remediation=rule_info.get('remediation', ''),
                    fix='',
                    references=rule_info.get('references', []),
                    tags=rule_info.get('tags', []),
                )
                
                findings.append(finding)
        except Exception as e:
            # Log error but continue
            pass
        
        return findings
    
    def _get_rule_info(self, identifier: str) -> Dict[str, Any]:
        """Get information about a PHPStan rule/identifier."""
        # This is a simplified mapping; PHPStan has many error codes
        rule_info = {
            'security': {
                'title': 'Security Issue',
                'description': 'General security issue detected',
                'remediation': 'Review the code for security vulnerabilities',
                'references': [],
                'tags': ['security'],
            },
            'sql-injection': {
                'title': 'SQL Injection',
                'description': 'Potential SQL injection vulnerability detected',
                'remediation': 'Use prepared statements or ORM methods',
                'references': ['https://owasp.org/www-community/attacks/SQL_Injection'],
                'tags': ['sqli', 'injection'],
            },
            'xss': {
                'title': 'Cross-Site Scripting',
                'description': 'Potential XSS vulnerability detected',
                'remediation': 'Escape output properly using htmlspecialchars() or similar',
                'references': ['https://owasp.org/www-community/attacks/xss'],
                'tags': ['xss', 'injection'],
            },
            'csrf': {
                'title': 'Cross-Site Request Forgery',
                'description': 'Missing CSRF protection detected',
                'remediation': 'Add CSRF tokens to forms and validate them',
                'references': ['https://owasp.org/www-community/attacks/csrf'],
                'tags': ['csrf'],
            },
            'path-traversal': {
                'title': 'Path Traversal',
                'description': 'Potential path traversal vulnerability detected',
                'remediation': 'Validate and sanitize file paths, use basename() and realpath()',
                'references': ['https://owasp.org/www-community/attacks/Path_Traversal'],
                'tags': ['path-traversal', 'lfi'],
            },
            'file-upload': {
                'title': 'File Upload Vulnerability',
                'description': 'Potential file upload vulnerability detected',
                'remediation': 'Validate file types, extensions, and content',
                'references': ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'],
                'tags': ['file-upload', 'rce'],
            },
            'command-injection': {
                'title': 'Command Injection',
                'description': 'Potential command injection vulnerability detected',
                'remediation': 'Use proper escaping and avoid passing user input to shell commands',
                'references': ['https://owasp.org/www-community/attacks/Command_Injection'],
                'tags': ['command-injection', 'rce'],
            },
            'rce': {
                'title': 'Remote Code Execution',
                'description': 'Potential remote code execution vulnerability detected',
                'remediation': 'Review code execution paths and sanitize all input',
                'references': ['https://owasp.org/www-community/attacks/Code_Injection'],
                'tags': ['rce'],
            },
            'hardcoded-password': {
                'title': 'Hardcoded Password',
                'description': 'Hardcoded password detected in code',
                'remediation': 'Remove hardcoded passwords and use environment variables or configuration files',
                'references': [],
                'tags': ['hardcoded-secret', 'credentials'],
            },
            'hardcoded-secret': {
                'title': 'Hardcoded Secret',
                'description': 'Hardcoded secret (API key, token, etc.) detected in code',
                'remediation': 'Remove hardcoded secrets and use environment variables or secret management',
                'references': [],
                'tags': ['hardcoded-secret', 'credentials'],
            },
            'eval': {
                'title': 'Eval Usage',
                'description': 'Use of eval() detected, which can lead to code injection',
                'remediation': 'Avoid using eval() with user-controlled input',
                'references': ['https://www.php.net/manual/en/function.eval.php'],
                'tags': ['code-injection', 'rce'],
            },
            'create_function': {
                'title': 'Create Function Usage',
                'description': 'Use of create_function() detected, which can lead to code injection',
                'remediation': 'Avoid using create_function() with user-controlled input',
                'references': ['https://www.php.net/manual/en/function.create-function.php'],
                'tags': ['code-injection', 'rce'],
            },
            'unserialize': {
                'title': 'Unserialize Usage',
                'description': 'Use of unserialize() with user-controlled input detected',
                'remediation': 'Avoid unserializing user-controlled input or use a safe unserializer',
                'references': ['https://owasp.org/www-community/attacks/Deserialization_attack'],
                'tags': ['deserialization', 'rce'],
            },
        }
        
        return rule_info.get(identifier.lower(), {
            'title': identifier,
            'description': '',
            'remediation': '',
            'references': [],
            'tags': [],
        })
