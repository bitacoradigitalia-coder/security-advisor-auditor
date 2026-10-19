"""
ESLint Security Analyzer for Security Advisor Auditor v3.0
Integrates with ESLint and eslint-plugin-security for JavaScript/TypeScript analysis.
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile
import os

from ..base_analyzer import BaseAnalyzer, Finding, ScanResult


class EslintAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses ESLint with security plugins for JavaScript/TypeScript.
    """
    
    TOOL_NAME = "eslint-security"
    SUPPORTED_LANGUAGES = ["javascript", "typescript", "js", "ts"]
    
    # ESLint security rules
    SECURITY_RULES = [
        'security/detect-object-injection',
        'security/detect-possible-timing-attacks',
        'security/detect-child-process',
        'security/detect-disable-mustache-escape',
        'security/detect-eval-with-expression',
        'security/detect-new-buffer',
        'security/detect-no-csrf-before-method-override',
        'security/detect-non-literal-fs-filename',
        'security/detect-non-literal-require',
        'security/detect-non-literal-regexp',
        'security/detect-pseudoRandomBytes',
        'security/detect-require-with-expression',
        'security/detect-unsafe-regex',
        'security/detect-bidi-characters',
        'security/detect-buffer-noassert',
        'security/detect-disable-mustache-escape',
        'security/detect-eval-with-expression',
        'security/detect-hidden-characters',
        'security/detect-incomplete-slice',
        'security/detect-inside-try',
        'security/detect-new-buffer',
        'security/detect-no-csrf-before-method-override',
        'security/detect-non-literal-fs-filename',
        'security/detect-non-literal-require',
        'security/detect-non-literal-regexp',
        'security/detect-object-injection',
        'security/detect-possible-timing-attacks',
        'security/detect-pseudoRandomBytes',
        'security/detect-require-with-expression',
        'security/detect-unsafe-regex',
    ]
    
    # Custom ESLint config for security
    ESLINT_CONFIG = {
        "root": True,
        "parserOptions": {
            "ecmaVersion": 2022,
            "sourceType": "module",
            "ecmaFeatures": {
                "jsx": True
            }
        },
        "env": {
            "browser": True,
            "es2022": True,
            "node": True
        },
        "plugins": ["security"],
        "extends": ["eslint:recommended", "plugin:security/recommended"],
        "rules": {
            "security/detect-object-injection": "error",
            "security/detect-child-process": "error",
            "security/detect-eval-with-expression": "error",
            "security/detect-new-buffer": "error",
            "security/detect-non-literal-fs-filename": "error",
            "security/detect-non-literal-require": "error",
            "security/detect-pseudoRandomBytes": "error",
        }
    }
    
    def __init__(self):
        """Initialize EslintAnalyzer."""
        super().__init__()
        self._available = self._check_eslint_installed()
    
    def _check_eslint_installed(self) -> bool:
        """Check if eslint and security plugin are installed."""
        try:
            # Check eslint
            result = subprocess.run(
                ['npx', 'eslint', '--version'],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return False
            
            # Check security plugin
            result = subprocess.run(
                ['npx', 'eslint', '--list-rules', 'security/'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    
    def is_available(self) -> bool:
        """Check if eslint-security is available."""
        return self._available
    
    def analyze_file(self, file_path: Union[str, Path], language: str = None) -> ScanResult:
        """
        Analyze a JavaScript/TypeScript file with ESLint Security.
        
        Args:
            file_path: Path to the file
            language: Language (javascript or typescript)
        
        Returns:
            ScanResult with findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language=language or "javascript",
                findings=[],
                errors=["ESLint or eslint-plugin-security is not installed"],
                success=False
            )
        
        file_path = Path(file_path)
        if not file_path.exists():
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language=language or "javascript",
                findings=[],
                errors=[f"File not found: {file_path}"],
                success=False
            )
        
        # Detect language if not provided
        lang = language or self._detect_language(file_path)
        
        # Build command
        cmd = ['npx', 'eslint']
        
        # Use security config
        cmd.extend(['-c', self._create_config_file()])
        
        # Specify language
        if lang == 'typescript':
            cmd.extend(['--parser', '@typescript-eslint/parser'])
        
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
                success=result.returncode == 0
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                target=str(file_path),
                tool=self.TOOL_NAME,
                language=lang,
                findings=[],
                errors=["ESLint analysis timed out"],
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
        Analyze JavaScript/TypeScript code directly with ESLint Security.
        
        Args:
            code: Source code
            language: Language (javascript or typescript)
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
                errors=["ESLint or eslint-plugin-security is not installed"],
                success=False
            )
        
        # Create temporary file
        extension = '.ts' if language == 'typescript' else '.js'
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix=extension,
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
        Analyze all JavaScript/TypeScript files in a directory.
        
        Args:
            dir_path: Path to the directory
            languages: Language filter (javascript, typescript)
        
        Returns:
            ScanResult with all findings
        """
        if not self.is_available():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "javascript,typescript",
                findings=[],
                errors=["ESLint or eslint-plugin-security is not installed"],
                success=False
            )
        
        dir_path = Path(dir_path)
        if not dir_path.exists():
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "javascript,typescript",
                findings=[],
                errors=[f"Directory not found: {dir_path}"],
                success=False
            )
        
        # Build command
        cmd = ['npx', 'eslint']
        
        # Use security config
        cmd.extend(['-c', self._create_config_file()])
        
        # Output format
        cmd.extend(['-f', 'json'])
        
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
                language=",".join(languages) if languages else "javascript,typescript",
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
                language=",".join(languages) if languages else "javascript,typescript",
                findings=[],
                errors=["ESLint analysis timed out"],
                success=False
            )
        except Exception as e:
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "javascript,typescript",
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension."""
        extension = file_path.suffix.lower()
        
        if extension in ['.ts', '.tsx']:
            return 'typescript'
        elif extension in ['.js', '.jsx', '.mjs', '.cjs']:
            return 'javascript'
        
        return 'javascript'
    
    def _create_config_file(self) -> str:
        """Create a temporary ESLint config file."""
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        ) as f:
            json.dump(self.ESLINT_CONFIG, f)
            return f.name
    
    def _parse_output(self, output: str, language: str = "javascript") -> List[Finding]:
        """Parse ESLint JSON output into Finding objects."""
        findings = []
        
        try:
            # ESLint outputs one JSON object per file, with an array of messages
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        # Handle both single file and multiple files output
        if isinstance(data, list):
            results = data
        else:
            results = [data]
        
        for result in results:
            for message in result.get('messages', []):
                # Only process security-related messages
                if not message.get('ruleId', '').startswith('security/'):
                    continue
                
                rule_id = message.get('ruleId', '')
                severity = message.get('severity', 2)  # 2 = error, 1 = warning
                
                # Map ESLint severity to ours
                if severity == 2:
                    finding_severity = 'high'
                elif severity == 1:
                    finding_severity = 'medium'
                else:
                    finding_severity = 'low'
                
                # Extract rule information
                rule_info = self._get_rule_info(rule_id)
                
                finding = Finding(
                    tool=self.TOOL_NAME,
                    language=language,
                    severity=finding_severity,
                    confidence='high',
                    type='vulnerability' if finding_severity in ['high', 'critical'] else 'risk',
                    category=rule_id,
                    title=rule_info.get('title', rule_id),
                    message=message.get('message', ''),
                    description=rule_info.get('description', message.get('message', '')),
                    file=result.get('filePath', ''),
                    line=message.get('line'),
                    column=message.get('column'),
                    code=message.get('source', ''),
                    evidence='',
                    proof_of_concept='',
                    remediation=rule_info.get('remediation', ''),
                    fix=message.get('fix', {}).get('text', ''),
                    references=rule_info.get('references', []),
                    tags=rule_info.get('tags', []),
                )
                
                findings.append(finding)
        
        return findings
    
    def _get_rule_info(self, rule_id: str) -> Dict[str, Any]:
        """Get information about a security rule."""
        # This is a simplified mapping; in a real implementation, we'd fetch from the plugin
        rule_info = {
            'security/detect-object-injection': {
                'title': 'Detect Object Injection',
                'description': 'Detects potential object injection vulnerabilities',
                'remediation': 'Use safe property access and avoid dynamic property assignment from user input',
                'references': ['https://owasp.org/www-community/attacks/Object_Injection'],
                'tags': ['injection', 'object-injection'],
            },
            'security/detect-child-process': {
                'title': 'Detect Child Process',
                'description': 'Detects the use of child_process module which can lead to command injection',
                'remediation': 'Use safer alternatives or properly sanitize input',
                'references': ['https://nodejs.org/api/child_process.html'],
                'tags': ['command-injection', 'rce'],
            },
            'security/detect-eval-with-expression': {
                'title': 'Detect Eval with Expression',
                'description': 'Detects the use of eval() with dynamic expressions',
                'remediation': 'Avoid using eval() with user-controlled input',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval'],
                'tags': ['code-injection', 'rce'],
            },
            'security/detect-new-buffer': {
                'title': 'Detect New Buffer',
                'description': 'Detects the use of the deprecated Buffer constructor',
                'remediation': 'Use Buffer.from(), Buffer.alloc(), or Buffer.allocUnsafe()',
                'references': ['https://nodejs.org/api/buffer.html'],
                'tags': ['deprecated-api', 'buffer'],
            },
            'security/detect-non-literal-fs-filename': {
                'title': 'Detect Non-literal FS Filename',
                'description': 'Detects file system operations with non-literal filenames',
                'remediation': 'Use literal strings for file paths or properly validate input',
                'references': ['https://owasp.org/www-community/attacks/Path_Traversal'],
                'tags': ['path-traversal', 'lfi'],
            },
            'security/detect-non-literal-require': {
                'title': 'Detect Non-literal Require',
                'description': 'Detects require() calls with dynamic paths',
                'remediation': 'Use literal strings for module paths or use a allowlist',
                'references': ['https://nodejs.org/api/modules.html'],
                'tags': ['module-injection', 'rce'],
            },
            'security/detect-pseudoRandomBytes': {
                'title': 'Detect Pseudo Random Bytes',
                'description': 'Detects the use of Math.random() for cryptographic purposes',
                'remediation': 'Use crypto.randomBytes() for cryptographic operations',
                'references': ['https://nodejs.org/api/crypto.html'],
                'tags': ['weak-crypto', 'randomness'],
            },
        }
        
        return rule_info.get(rule_id, {
            'title': rule_id,
            'description': '',
            'remediation': '',
            'references': [],
            'tags': [],
        })
