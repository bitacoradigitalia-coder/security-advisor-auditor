"""
Multi-Language Static Analysis Orchestrator for Security Advisor Auditor v3.0
Coordinates analysis across multiple tools and languages.

Supported Languages:
- Python (Bandit + Semgrep)
- JavaScript/TypeScript (ESLint Security + Semgrep)
- PHP (PHPStan Security + Semgrep)
- Java (Semgrep)
- Go (Semgrep)
- Ruby (Semgrep)
- C/C++ (Semgrep)
- And 20+ more via Semgrep
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from .base_analyzer import BaseAnalyzer, Finding, ScanResult
from .external import (
    SemgrepAnalyzer,
    NucleiAnalyzer,
    BanditAnalyzer,
    EslintAnalyzer,
    PHPStanAnalyzer,
)


class MultiLanguageAnalyzer(BaseAnalyzer):
    """
    Orchestrates static analysis across multiple tools and languages.
    
    This class provides a unified interface for analyzing code in multiple
    programming languages using the appropriate tools for each language.
    """
    
    TOOL_NAME = "multi_language"
    SUPPORTED_LANGUAGES = [
        'python', 'javascript', 'typescript', 'php', 'java', 'go', 'ruby',
        'c', 'cpp', 'csharp', 'rust', 'kotlin', 'scala', 'swift',
        'dart', 'elixir', 'erlang', 'haskell', 'lua', 'perl', 'r',
        'sql', 'yaml', 'json', 'xml', 'html', 'bash', 'dockerfile',
    ]
    
    # Tool mapping: language -> list of tools to use
    LANGUAGE_TOOLS = {
        'python': ['bandit', 'semgrep'],
        'javascript': ['eslint', 'semgrep'],
        'typescript': ['eslint', 'semgrep'],
        'php': ['phpstan', 'semgrep'],
        'java': ['semgrep'],
        'go': ['semgrep'],
        'ruby': ['semgrep'],
        'c': ['semgrep'],
        'cpp': ['semgrep'],
        'csharp': ['semgrep'],
        'rust': ['semgrep'],
        'kotlin': ['semgrep'],
        'scala': ['semgrep'],
        'swift': ['semgrep'],
        'dart': ['semgrep'],
        'elixir': ['semgrep'],
        'erlang': ['semgrep'],
        'haskell': ['semgrep'],
        'lua': ['semgrep'],
        'perl': ['semgrep'],
        'r': ['semgrep'],
        'sql': ['semgrep'],
        'yaml': ['semgrep'],
        'json': ['semgrep'],
        'xml': ['semgrep'],
        'html': ['semgrep'],
        'bash': ['semgrep'],
        'dockerfile': ['semgrep'],
    }
    
    # Tool instances cache
    _tool_instances: Dict[str, BaseAnalyzer] = {}
    
    def __init__(self, use_all_tools: bool = False):
        """
        Initialize MultiLanguageAnalyzer.
        
        Args:
            use_all_tools: If True, use all available tools for each language.
                         If False, use only the primary tool.
        """
        super().__init__()
        self.use_all_tools = use_all_tools
        self._analyzers = {}
    
    def _get_analyzer(self, tool_name: str) -> Optional[BaseAnalyzer]:
        """Get or create an analyzer instance."""
        if tool_name not in self._analyzers:
            tool_map = {
                'semgrep': SemgrepAnalyzer,
                'nuclei': NucleiAnalyzer,
                'bandit': BanditAnalyzer,
                'eslint': EslintAnalyzer,
                'phpstan': PHPStanAnalyzer,
            }
            
            if tool_name in tool_map:
                self._analyzers[tool_name] = tool_map[tool_name]()
            else:
                return None
        
        return self._analyzers[tool_name]
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages."""
        return self.SUPPORTED_LANGUAGES
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get availability status of all tools."""
        tools = {}
        for tool_name in ['semgrep', 'nuclei', 'bandit', 'eslint', 'phpstan']:
            analyzer = self._get_analyzer(tool_name)
            tools[tool_name] = analyzer.is_available() if analyzer else False
        return tools
    
    def analyze_file(
        self,
        file_path: Union[str, Path],
        language: str = None,
        tools: List[str] = None
    ) -> ScanResult:
        """
        Analyze a file with appropriate tools for its language.
        
        Args:
            file_path: Path to the file
            language: Language of the file (auto-detected if not provided)
            tools: Specific tools to use (overrides language mapping)
        
        Returns:
            ScanResult with all findings
        """
        file_path = Path(file_path)
        
        # Detect language if not provided
        if language is None:
            language = self._detect_language(file_path)
        
        # Get tools to use
        if tools is None:
            tools = self.LANGUAGE_TOOLS.get(language.lower(), ['semgrep'])
        
        # Collect all findings
        all_findings: List[Finding] = []
        all_errors: List[str] = []
        
        for tool_name in tools:
            analyzer = self._get_analyzer(tool_name)
            if not analyzer or not analyzer.is_available():
                all_errors.append(f"Tool '{tool_name}' not available for {language}")
                continue
            
            # Analyze with this tool
            result = analyzer.analyze_file(file_path, language)
            
            if result.success:
                all_findings.extend(result.findings)
            else:
                all_errors.extend(result.errors)
        
        # Create combined result
        return ScanResult(
            target=str(file_path),
            tool=self.TOOL_NAME,
            language=language,
            findings=all_findings,
            statistics={
                'by_severity': self._count_by_severity(all_findings),
                'by_category': self._count_by_category(all_findings),
                'by_tool': self._count_by_tool(all_findings),
            },
            errors=all_errors,
            success=len(all_findings) > 0 or len(all_errors) == 0
        )
    
    def analyze_code(
        self,
        code: str,
        language: str,
        file_path: str = "<stdin>"
    ) -> ScanResult:
        """
        Analyze code directly with appropriate tools.
        
        Args:
            code: Source code
            language: Language of the code
            file_path: Virtual file path
        
        Returns:
            ScanResult with findings
        """
        # Get tools to use
        tools = self.LANGUAGE_TOOLS.get(language.lower(), ['semgrep'])
        
        # Collect all findings
        all_findings: List[Finding] = []
        all_errors: List[str] = []
        
        for tool_name in tools:
            analyzer = self._get_analyzer(tool_name)
            if not analyzer or not analyzer.is_available():
                all_errors.append(f"Tool '{tool_name}' not available for {language}")
                continue
            
            # Analyze with this tool
            result = analyzer.analyze_code(code, language, file_path)
            
            if result.success:
                all_findings.extend(result.findings)
            else:
                all_errors.extend(result.errors)
        
        # Create combined result
        return ScanResult(
            target=file_path,
            tool=self.TOOL_NAME,
            language=language,
            findings=all_findings,
            statistics={
                'by_severity': self._count_by_severity(all_findings),
                'by_category': self._count_by_category(all_findings),
                'by_tool': self._count_by_tool(all_findings),
            },
            errors=all_errors,
            success=len(all_findings) > 0 or len(all_errors) == 0
        )
    
    def analyze_directory(
        self,
        dir_path: Union[str, Path],
        languages: List[str] = None,
        tools: List[str] = None
    ) -> ScanResult:
        """
        Analyze all files in a directory.
        
        Args:
            dir_path: Path to the directory
            languages: List of languages to analyze (all supported if None)
            tools: Specific tools to use (overrides language mapping)
        
        Returns:
            ScanResult with all findings
        """
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
        
        # Get all files in directory
        all_files = list(self._get_all_files(dir_path))
        
        if not all_files:
            return ScanResult(
                target=str(dir_path),
                tool=self.TOOL_NAME,
                language=",".join(languages) if languages else "",
                findings=[],
                errors=["No files found in directory"],
                success=True
            )
        
        # Filter by language if specified
        if languages:
            languages_lower = [lang.lower() for lang in languages]
            all_files = [
                f for f in all_files
                if self._detect_language(f).lower() in languages_lower
            ]
        
        # Collect all findings
        all_findings: List[Finding] = []
        all_errors: List[str] = []
        
        for file_path in all_files:
            language = self._detect_language(file_path)
            
            # Get tools to use
            if tools is None:
                file_tools = self.LANGUAGE_TOOLS.get(language.lower(), ['semgrep'])
            else:
                file_tools = tools
            
            for tool_name in file_tools:
                analyzer = self._get_analyzer(tool_name)
                if not analyzer or not analyzer.is_available():
                    all_errors.append(f"Tool '{tool_name}' not available for {file_path}")
                    continue
                
                # Analyze with this tool
                result = analyzer.analyze_file(file_path, language)
                
                if result.success:
                    all_findings.extend(result.findings)
                else:
                    all_errors.extend(result.errors)
        
        # Create combined result
        return ScanResult(
            target=str(dir_path),
            tool=self.TOOL_NAME,
            language=",".join(languages) if languages else "",
            findings=all_findings,
            statistics={
                'by_severity': self._count_by_severity(all_findings),
                'by_category': self._count_by_category(all_findings),
                'by_tool': self._count_by_tool(all_findings),
                'by_language': self._count_by_language(all_findings),
                'files_scanned': len(all_files),
            },
            errors=all_errors,
            success=len(all_findings) > 0 or len(all_errors) == 0
        )
    
    def scan_url(
        self,
        url: str,
        tools: List[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Scan a URL with Nuclei (for web vulnerability scanning).
        
        Args:
            url: URL to scan
            tools: Specific tools to use (default: nuclei)
            **kwargs: Additional options for the tools
        
        Returns:
            ScanResult with findings
        """
        if tools is None:
            tools = ['nuclei']
        
        # Only Nuclei supports URL scanning
        nuclei_results = []
        all_errors = []
        
        for tool_name in tools:
            if tool_name == 'nuclei':
                analyzer = self._get_analyzer('nuclei')
                if analyzer and analyzer.is_available():
                    result = analyzer.scan_url(url, **kwargs)
                    if result.success:
                        nuclei_results.extend(result.findings)
                    else:
                        all_errors.extend(result.errors)
            else:
                all_errors.append(f"Tool '{tool_name}' does not support URL scanning")
        
        return ScanResult(
            target=url,
            tool=self.TOOL_NAME,
            language="",
            findings=nuclei_results,
            statistics={
                'by_severity': self._count_by_severity(nuclei_results),
                'by_category': self._count_by_category(nuclei_results),
            },
            errors=all_errors,
            success=len(nuclei_results) > 0 or len(all_errors) == 0
        )
    
    def scan_targets(
        self,
        targets: List[str],
        tools: List[str] = None,
        **kwargs
    ) -> Dict[str, ScanResult]:
        """
        Scan multiple targets (files or URLs).
        
        Args:
            targets: List of file paths or URLs
            tools: Specific tools to use
            **kwargs: Additional options
        
        Returns:
            Dictionary mapping target to ScanResult
        """
        results = {}
        
        for target in targets:
            # Check if it's a URL or file
            if target.startswith(('http://', 'https://')):
                results[target] = self.scan_url(target, tools, **kwargs)
            else:
                results[target] = self.analyze_file(target, tools=tools)
        
        return results
    
    def _detect_language(self, file_path: Union[str, Path]) -> str:
        """Detect language from file extension."""
        file_path = Path(file_path)
        extension = file_path.suffix.lower()
        
        # Check for known extensions
        language_map = {
            # Python
            '.py': 'python',
            '.pyw': 'python',
            '.pyx': 'python',
            
            # JavaScript/TypeScript
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.mjs': 'javascript',
            '.cjs': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            
            # PHP
            '.php': 'php',
            '.phtml': 'php',
            '.php3': 'php',
            '.php4': 'php',
            '.php5': 'php',
            '.php7': 'php',
            '.php8': 'php',
            
            # Java
            '.java': 'java',
            
            # Go
            '.go': 'go',
            
            # Ruby
            '.rb': 'ruby',
            '.rbw': 'ruby',
            
            # C/C++
            '.c': 'c',
            '.h': 'c',
            '.cpp': 'cpp',
            '.hpp': 'cpp',
            '.cxx': 'cpp',
            '.hxx': 'cpp',
            '.cc': 'cpp',
            
            # C#
            '.cs': 'csharp',
            
            # Rust
            '.rs': 'rust',
            
            # Kotlin
            '.kt': 'kotlin',
            '.kts': 'kotlin',
            
            # Scala
            '.scala': 'scala',
            '.sc': 'scala',
            
            # Swift
            '.swift': 'swift',
            
            # Dart
            '.dart': 'dart',
            
            # Elixir
            '.ex': 'elixir',
            '.exs': 'elixir',
            
            # Erlang
            '.erl': 'erlang',
            '.hrl': 'erlang',
            
            # Haskell
            '.hs': 'haskell',
            '.lhs': 'haskell',
            
            # Lua
            '.lua': 'lua',
            
            # Perl
            '.pl': 'perl',
            '.pm': 'perl',
            
            # R
            '.r': 'r',
            '.R': 'r',
            
            # SQL
            '.sql': 'sql',
            
            # YAML
            '.yaml': 'yaml',
            '.yml': 'yaml',
            
            # JSON
            '.json': 'json',
            
            # XML
            '.xml': 'xml',
            
            # HTML
            '.html': 'html',
            '.htm': 'html',
            '.xhtml': 'html',
            
            # Bash
            '.sh': 'bash',
            '.bash': 'bash',
            '.zsh': 'bash',
            
            # Docker
            'dockerfile': 'dockerfile',
            'Dockerfile': 'dockerfile',
        }
        
        return language_map.get(extension, 'generic')
    
    def _get_all_files(self, dir_path: Path) -> List[Path]:
        """Get all files recursively from a directory."""
        all_files = []
        
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                # Skip hidden files and common non-source directories
                if not file.startswith('.') and not self._is_excluded_dir(file_path):
                    all_files.append(file_path)
        
        return all_files
    
    def _is_excluded_dir(self, file_path: Path) -> bool:
        """Check if a file is in an excluded directory."""
        excluded_dirs = [
            '.git', '.svn', '.hg',
            'node_modules', 'vendor', 'bower_components',
            '__pycache__', '.pytest_cache', '.mypy_cache',
            'dist', 'build', 'target', 'out',
            'logs', 'log',
            'tmp', 'temp',
            '.vscode', '.idea', '.settings',
        ]
        
        for part in file_path.parts:
            if part in excluded_dirs or part.startswith('.') and part != '.':
                return True
        
        return False
    
    def _count_by_tool(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by tool."""
        counts = {}
        for finding in findings:
            tool = finding.tool
            counts[tool] = counts.get(tool, 0) + 1
        return counts
    
    def _count_by_language(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by language."""
        counts = {}
        for finding in findings:
            language = finding.language
            if language:
                counts[language] = counts.get(language, 0) + 1
        return counts
