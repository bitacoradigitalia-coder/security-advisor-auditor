"""
Semgrep Analyzer for Security Advisor Auditor v3.0
Integrates with Semgrep for static analysis of 30+ programming languages.

Supported Languages:
- Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++, C#, Rust
- And 20+ more languages via Semgrep rules
"""

import subprocess
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile
import os

from ..base_analyzer import BaseAnalyzer, Finding, ScanResult


class SemgrepAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses Semgrep for static analysis.
    Semgrep is a fast, open-source static analysis tool for many languages.
    """
    
    TOOL_NAME = "semgrep"
    SUPPORTED_LANGUAGES = [
        'python', 'javascript', 'typescript', 'java', 'go', 'ruby',
        'php', 'c', 'cpp', 'csharp', 'rust', 'kotlin', 'scala',
        'swift', 'dart', 'elixir', 'erlang', 'haskell', 'lua',
        'perl', 'r', 'sql', 'yaml', 'json', 'xml', 'html',
        'bash', 'dockerfile', 'regex', 'generic'
    ]
    
    # Default security rules
    DEFAULT_RULES = [
        'p/security-audit',
        'p/secrets',
        'p/owasp-top-ten',
        'p/cwe-top-25',
        'p/java-security',
        'p/javascript-security',
        'p/python-security',
        'p/php-security',
    ]
    
    # Custom rules directory
    CUSTOM_RULES_DIR = None
    
    def __init__(self, custom_rules_dir: str = None, use_default_rules: bool = True):
        """
        Initialize SemgrepAnalyzer.
        
        Args:
            custom_rules_dir: Path to custom Semgrep rules directory
            use_default_rules: Whether to use default security rules
        """
        super().__init__()
        self.custom_rules_dir = custom_rules_dir
        self.use_default_rules = use_default_rules
        self._available = self._check_semgrep_installed()
    
    def _check_semgrep_installed(self) -> bool:
        """Check if semgrep is installed and accessible."""
        try:
            result = subprocess.run(
                ['semgrep', '--version'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def is_available(self) -> bool:
        """Check if semgrep is available."""
        return self._available
    
    def analyze_file(self, file_path: Union[str, Path], language: str = None) -> ScanResult:
        """
        Analyze a single file with Semgrep.
        
        Args:
            file_path: Path to the file to analyze
            language: Language of the file (optional)
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language=language or "",
                findings=[],
                errors=["Semgrep is not installed"],
                success=False
            )
        
        file_path = Path(file_path)
        if not file_path.exists():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language=language or "",
                findings=[],
                errors=[f"File not found: {file_path}"],
                success=False
            )
        
        # Detect language if not provided
        lang = language or self._detect_language(file_path)
        
        # Build command
        cmd = ['semgrep']
        
        # Add language if specified
        if lang:
            cmd.extend(['--lang', lang])
        
        # Add rules
        rules = []
        if self.use_default_rules:
            rules.extend(self.DEFAULT_RULES)
        if self.custom_rules_dir:
            rules.append(str(self.custom_rules_dir))
        
        for rule in rules:
            cmd.extend(['--config', rule])
        
        # Output format
        cmd.extend(['--json'])
        
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
            
            if result.returncode != 0:
                return ScanResult(
                    target=str(file_path),
                    tool=self.TOOL_NAME,
                    language=lang,
                    findings=[],
                    errors=[result.stderr],
                    success=False
                )
            
            # Parse output
            findings = self._parse_output(result.stdout, lang)
            
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language=lang,
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
                language=lang,
                findings=[],
                errors=["Semgrep analysis timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language=lang,
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def analyze_code(self, code: str, language: str, file_path: str = "<stdin>") -> ScanResult:
        """
        Analyze code directly with Semgrep.
        
        Args:
            code: Source code to analyze
            language: Language of the code
            file_path: Virtual file path
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=file_path,
                tool=self.TOOL_NAME,
                language=language,
                findings=[],
                errors=["Semgrep is not installed"],
                success=False
            )
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix=self._get_extension(language),
            delete=False
        ) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            result = self.analyze_file(temp_path, language)
            return result
        finally:
            # Clean up
            try:
                os.unlink(temp_path)
            except:
                pass
    
    def analyze_directory(self, dir_path: Union[str, Path], languages: List[str] = None) -> ScanResult:
        """
        Analyze all files in a directory with Semgrep.
        
        Args:
            dir_path: Path to the directory
            languages: List of languages to analyze (optional)
        
        Returns:
            ScanResult with all findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "",
                findings=[],
                errors=["Semgrep is not installed"],
                success=False
            )
        
        dir_path = Path(dir_path)
        if not dir_path.exists():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "",
                findings=[],
                errors=[f"Directory not found: {dir_path}"],
                success=False
            )
        
        # Build command
        cmd = ['semgrep']
        
        # Add languages if specified
        if languages:
            cmd.extend(['--lang', ','.join(languages)])
        
        # Add rules
        rules = []
        if self.use_default_rules:
            rules.extend(self.DEFAULT_RULES)
        if self.custom_rules_dir:
            rules.append(str(self.custom_rules_dir))
        
        for rule in rules:
            cmd.extend(['--config', rule])
        
        # Output format
        cmd.extend(['--json'])
        
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
            
            if result.returncode != 0:
                return ScanResult(
                    target=str(dir_path),
                    tool=self.TOOL_NAME,
                    language=",".join(languages) if languages else "",
                    findings=[],
                    errors=[result.stderr],
                    success=False
                )
            
            # Parse output
            findings = self._parse_output(result.stdout)
            
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "",
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
                language=",".join(languages) if languages else "",
                findings=[],
                errors=["Semgrep analysis timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "",
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension."""
        extension = file_path.suffix.lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.cs': 'csharp',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.swift': 'swift',
            '.dart': 'dart',
            '.ex': 'elixir',
            '.erl': 'erlang',
            '.hs': 'haskell',
            '.lua': 'lua',
            '.pl': 'perl',
            '.r': 'r',
            '.sql': 'sql',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.json': 'json',
            '.xml': 'xml',
            '.html': 'html',
            '.sh': 'bash',
            'dockerfile': 'dockerfile',
        }
        
        return language_map.get(extension, 'generic')
    
    def _get_extension(self, language: str) -> str:
        """Get file extension for a language."""
        extension_map = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'go': '.go',
            'ruby': '.rb',
            'php': '.php',
            'c': '.c',
            'cpp': '.cpp',
            'csharp': '.cs',
            'rust': '.rs',
            'kotlin': '.kt',
            'scala': '.scala',
            'swift': '.swift',
            'dart': '.dart',
            'elixir': '.ex',
            'erlang': '.erl',
            'haskell': '.hs',
            'lua': '.lua',
            'perl': '.pl',
            'r': '.r',
            'sql': '.sql',
            'yaml': '.yaml',
            'json': '.json',
            'xml': '.xml',
            'html': '.html',
            'bash': '.sh',
            'dockerfile': 'Dockerfile',
        }
        
        return extension_map.get(language, '.txt')
    
    def _parse_output(self, output: str, language: str = None) -> List[Finding]:
        """Parse Semgrep JSON output into Finding objects."""
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        for result in data.get('results', []):
            finding = self.normalize_finding(result, language)
            
            # Extract additional Semgrep-specific fields
            extra = result.get('extra', {})
            
            # Map Semgrep severity to our severity
            semgrep_severity = extra.get('severity', '').lower()
            if semgrep_severity:
                finding.severity = self.SEVERITY_MAP.get(semgrep_severity, 'medium')
            
            # Map Semgrep metadata
            finding.category = extra.get('rule_id', extra.get('check_id', ''))
            finding.title = extra.get('message', result.get('extra', {}).get('message', ''))
            finding.description = extra.get('message', '')
            
            # Location
            start = result.get('start', {})
            end = result.get('end', {})
            finding.line = start.get('line')
            finding.column = start.get('col')
            finding.code = result.get('extra', {}).get('lines', '')
            
            # Fix information
            finding.fix = extra.get('fix', '')
            
            # References
            if 'metadata' in extra:
                metadata = extra.get('metadata', {})
                finding.references = metadata.get('references', [])
                finding.tags = metadata.get('tags', [])
                finding.cvss_score = metadata.get('cvss_score')
                finding.cvss_vector = metadata.get('cvss_vector', '')
            
            findings.append(finding)
        
        return findings
