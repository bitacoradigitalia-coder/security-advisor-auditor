"""
Bandit Analyzer for Security Advisor Auditor v3.0
Integrates with Bandit for Python static analysis.

Bandit is a tool designed to find common security issues in Python code.
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile
import os

from ..base_analyzer import BaseAnalyzer, Finding, ScanResult


class BanditAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses Bandit for Python static analysis.
    Bandit finds common security issues in Python code.
    """
    
    TOOL_NAME = "bandit"
    SUPPORTED_LANGUAGES = ["python"]
    
    # Bandit severity levels
    BANDIT_SEVERITY_MAP = {
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
    }
    
    # Bandit confidence levels
    BANDIT_CONFIDENCE_MAP = {
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
    }
    
    def __init__(self):
        """Initialize BanditAnalyzer."""
        super().__init__()
        self._available = self._check_bandit_installed()
    
    def _check_bandit_installed(self) -> bool:
        """Check if bandit is installed and accessible."""
        try:
            result = subprocess.run(
                ['bandit', '--version'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def is_available(self) -> bool:
        """Check if bandit is available."""
        return self._available
    
    def analyze_file(self, file_path: Union[str, Path], language: str = None) -> ScanResult:
        """
        Analyze a single Python file with Bandit.
        
        Args:
            file_path: Path to the Python file
            language: Language (ignored, always python)
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=["Bandit is not installed"],
                success=False
            )
        
        file_path = Path(file_path)
        if not file_path.exists():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=[f"File not found: {file_path}"],
                success=False
            )
        
        # Build command
        cmd = ['bandit']
        
        # Recursive mode (for single file, this will just scan the file)
        cmd.append('-r')
        
        # Output format
        cmd.extend(['-f', 'json'])
        
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
            
            if result.returncode not in [0, 1]:  # Bandit returns 1 if findings found
                return ScanResult(
                    target=str(file_path),
                    tool=self.TOOL_NAME,
                    language="python",
                    findings=[],
                    errors=[result.stderr],
                    success=False
                )
            
            # Parse output
            findings = self._parse_output(result.stdout)
            
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=findings,
                statistics={
                    'by_severity': self._count_by_severity(findings),
                    'by_category': self._count_by_category(findings),
                },
                success=True
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=["Bandit analysis timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def analyze_code(self, code: str, language: str = "python", file_path: str = "<stdin>") -> ScanResult:
        """
        Analyze Python code directly with Bandit.
        
        Args:
            code: Python source code
            language: Language (ignored, always python)
            file_path: Virtual file path
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=file_path,
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=["Bandit is not installed"],
                success=False
            )
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            delete=False
        ) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            result = self.analyze_file(temp_path, "python")
            return result
        finally:
            # Clean up
            try:
                os.unlink(temp_path)
            except:
                pass
    
    def analyze_directory(self, dir_path: Union[str, Path], languages: List[str] = None) -> ScanResult:
        """
        Analyze all Python files in a directory with Bandit.
        
        Args:
            dir_path: Path to the directory
            languages: Language filter (ignored, always python)
        
        Returns:
            ScanResult with all findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=["Bandit is not installed"],
                success=False
            )
        
        dir_path = Path(dir_path)
        if not dir_path.exists():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=[f"Directory not found: {dir_path}"],
                success=False
            )
        
        # Build command
        cmd = ['bandit']
        
        # Recursive mode
        cmd.append('-r')
        
        # Output format
        cmd.extend(['-f', 'json'])
        
        # Target
        cmd.append(str(dir_path))
        
        # Execute
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )
            
            if result.returncode not in [0, 1]:
                return ScanResult(
                    target=str(dir_path),
                    tool=self.TOOL_NAME,
                    language="python",
                    findings=[],
                    errors=[result.stderr],
                    success=False
                )
            
            # Parse output
            findings = self._parse_output(result.stdout)
            
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=findings,
                statistics={
                    'by_severity': self._count_by_severity(findings),
                    'by_category': self._count_by_category(findings),
                },
                success=True
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=["Bandit analysis timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language="python",
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def _parse_output(self, output: str) -> List[Finding]:
        """Parse Bandit JSON output into Finding objects."""
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        for result in data.get('results', []):
            # Extract issue information
            issue = result.get('issue', '')
            severity = result.get('issue_severity', 'MEDIUM')
            confidence = result.get('issue_confidence', 'MEDIUM')
            text = result.get('issue_text', '')
            
            # Extract location
            filename = result.get('filename', '')
            line_number = result.get('line_number', None)
            
            # Extract code
            code = result.get('code', '')
            
            # Extract test ID and CWE
            test_id = result.get('test_id', '')
            cwe = result.get('cwe', None)
            
            finding = Finding(
                tool=self.TOOL_NAME,
                language="python",
                severity=self.BANDIT_SEVERITY_MAP.get(severity, 'medium'),
                confidence=self.BANDIT_CONFIDENCE_MAP.get(confidence, 'medium'),
                type='vulnerability' if severity == 'HIGH' else 'risk',
                category=test_id,
                title=issue,
                message=text,
                description=text,
                file=filename,
                line=line_number,
                column=None,
                code=code,
                evidence='',
                proof_of_concept='',
                remediation='',
                fix='',
                references=[f'https://bandit.readthedocs.io/en/latest/plugins/{test_id}.html'] if test_id else [],
                tags=[f'CWE-{cwe}'] if cwe else [],
            )
            
            # Add more specific information based on test_id
            if test_id == 'B101':  # assert_used
                finding.category = 'assert_used'
                finding.remediation = 'Remove assert statements or replace with proper error handling'
            elif test_id == 'B104':  # hardcoded_bind_all_interfaces
                finding.category = 'hardcoded_bind_all'
                finding.remediation = 'Bind to specific interfaces instead of 0.0.0.0'
            elif test_id == 'B105':  # hardcoded_password
                finding.category = 'hardcoded_password'
                finding.severity = 'critical'
                finding.remediation = 'Remove hardcoded passwords and use environment variables or secrets management'
            elif test_id == 'B107':  # hardcoded_password_funcarg
                finding.category = 'hardcoded_password_funcarg'
                finding.severity = 'critical'
            elif test_id == 'B108':  # hardcoded_tmp_directory
                finding.category = 'hardcoded_tmp'
            elif test_id == 'B110':  # subprocess_popen_with_shell_equals_true
                finding.category = 'shell_injection'
                finding.severity = 'high'
                finding.remediation = 'Avoid shell=True in subprocess calls'
            elif test_id == 'B112':  # try_except_pass
                finding.category = 'silent_exception'
            elif test_id == 'B113':  # requests_without_timeout
                finding.category = 'missing_timeout'
            elif test_id == 'B301':  # pickle
                finding.category = 'pickle_deserialization'
                finding.severity = 'high'
            elif test_id == 'B303':  # md5
                finding.category = 'weak_hash'
                finding.remediation = 'Use stronger hash algorithms like SHA-256'
            elif test_id == 'B307':  # eval
                finding.category = 'code_injection'
                finding.severity = 'critical'
            elif test_id == 'B311':  # subprocess
                finding.category = 'subprocess_injection'
            elif test_id == 'B320':  # hidden_files
                finding.category = 'hidden_file'
            elif test_id == 'B403':  # import_subprocess
                finding.category = 'subprocess_import'
            elif test_id == 'B404':  # subprocess_call_with_shell
                finding.category = 'shell_injection'
                finding.severity = 'high'
            elif test_id == 'B506':  # yaml_load
                finding.category = 'yaml_deserialization'
                finding.severity = 'high'
            elif test_id == 'B601':  # paramiko_calls
                finding.category = 'paramiko_security'
            elif test_id == 'B602':  # subprocess_popen_with_shell_equals_true
                finding.category = 'shell_injection'
                finding.severity = 'high'
            elif test_id == 'B603':  # subprocess_call_without_shell_equals_true
                finding.category = 'subprocess_security'
            elif test_id == 'B608':  # sql_injection
                finding.category = 'sqli'
                finding.severity = 'critical'
            
            findings.append(finding)
        
        return findings
