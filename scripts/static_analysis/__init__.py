"""
Static Analysis Module for Security Advisor Auditor v2.2
Multi-language support for vulnerability detection in source code.

Supported Languages:
- Python (native AST analysis + Bandit)
- JavaScript (native regex analyzer + ESLint Security + Semgrep)
- TypeScript (native regex analyzer + ESLint Security + Semgrep)
- PHP (native regex analyzer + PHPStan Security + Semgrep)
- IaC/CI-CD: Dockerfile, K8s, Terraform, GitHub Actions (v2.3, mejora M13)
- Java, Go, Ruby, C/C++ and 20+ more via Semgrep
"""

from .base_analyzer import BaseAnalyzer, Finding, ScanResult
from .multi_language import MultiLanguageAnalyzer
from .regex_rules import Rule, RuleEngine
from .js_analyzer import JavaScriptAnalyzer
from .ts_analyzer import TypeScriptAnalyzer
from .php_analyzer import PHPAnalyzer
from .iac_analyzer import IaCAnalyzer

# Import external analyzers (require the external CLI tool installed)
from .external import (
    SemgrepAnalyzer,
    NucleiAnalyzer,
    BanditAnalyzer,
    EslintAnalyzer,
    PHPStanAnalyzer,
)

__all__ = [
    'BaseAnalyzer',
    'Finding',
    'ScanResult',
    'MultiLanguageAnalyzer',
    'Rule',
    'RuleEngine',
    'JavaScriptAnalyzer',
    'TypeScriptAnalyzer',
    'PHPAnalyzer',
    'IaCAnalyzer',
    'SemgrepAnalyzer',
    'NucleiAnalyzer',
    'BanditAnalyzer',
    'EslintAnalyzer',
    'PHPStanAnalyzer',
]


def get_analyzer(language: str = None, tool: str = None):
    """
    Get the appropriate analyzer based on language or tool.

    Args:
        language: Target language (python, javascript, typescript, php, docker, yaml, terraform, etc.)
        tool: Specific tool to use (js_native, ts_native, php_native, iac_native, semgrep, bandit, eslint, etc.)

    Returns:
        Analyzer instance
    """
    if tool:
        tools_map = {
            'js_native': JavaScriptAnalyzer,
            'ts_native': TypeScriptAnalyzer,
            'php_native': PHPAnalyzer,
            'iac_native': IaCAnalyzer,
            'semgrep': SemgrepAnalyzer,
            'nuclei': NucleiAnalyzer,
            'bandit': BanditAnalyzer,
            'eslint': EslintAnalyzer,
            'phpstan': PHPStanAnalyzer,
        }
        if tool in tools_map:
            return tools_map[tool]()

    if language:
        # Analizadores nativos: sin dependencias externas
        native_map = {
            'javascript': JavaScriptAnalyzer,
            'js': JavaScriptAnalyzer,
            'jsx': JavaScriptAnalyzer,
            'typescript': TypeScriptAnalyzer,
            'ts': TypeScriptAnalyzer,
            'tsx': TypeScriptAnalyzer,
            'php': PHPAnalyzer,
            'docker': IaCAnalyzer,
            'dockerfile': IaCAnalyzer,
            'yaml': IaCAnalyzer,
            'yml': IaCAnalyzer,
            'terraform': IaCAnalyzer,
            'hcl': IaCAnalyzer,
            'k8s': IaCAnalyzer,
            'iac': IaCAnalyzer,
        }
        if language in native_map:
            return native_map[language]()

    # Return multi-language analyzer for comprehensive analysis
    return MultiLanguageAnalyzer()
