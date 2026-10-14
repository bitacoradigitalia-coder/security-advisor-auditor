"""
Static Analysis Module for Security Advisor Auditor v3.0
Multi-language support for vulnerability detection in source code.

Supported Languages:
- Python (native AST analysis + Bandit)
- JavaScript/TypeScript (ESLint Security + Semgrep)
- PHP (PHPStan Security + Semgrep)
- Java (Semgrep)
- Go (Semgrep)
- Ruby (Semgrep)
- C/C++ (Semgrep)
- And 20+ more via Semgrep
"""

from .base_analyzer import BaseAnalyzer
from .multi_language import MultiLanguageAnalyzer

# Import external analyzers
from .external import (
    SemgrepAnalyzer,
    NucleiAnalyzer,
    BanditAnalyzer,
    EslintAnalyzer,
    PHPStanAnalyzer,
)

__all__ = [
    'BaseAnalyzer',
    'MultiLanguageAnalyzer',
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
        language: Target language (python, javascript, php, etc.)
        tool: Specific tool to use (semgrep, bandit, eslint, etc.)
    
    Returns:
        Analyzer instance
    """
    if tool:
        tools_map = {
            'semgrep': SemgrepAnalyzer,
            'nuclei': NucleiAnalyzer,
            'bandit': BanditAnalyzer,
            'eslint': EslintAnalyzer,
            'phpstan': PHPStanAnalyzer,
        }
        if tool in tools_map:
            return tools_map[tool]()
    
    # Return multi-language analyzer for comprehensive analysis
    return MultiLanguageAnalyzer()
