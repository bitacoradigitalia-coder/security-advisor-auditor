"""
External Static Analysis Tools Integration for Security Advisor Auditor v3.0
Integrates with external security analysis tools (Semgrep, Nuclei, Bandit, etc.).
"""

from .semgrep_analyzer import SemgrepAnalyzer
from .nuclei_analyzer import NucleiAnalyzer
from .bandit_analyzer import BanditAnalyzer
from .eslint_analyzer import EslintAnalyzer
from .phpstan_analyzer import PHPStanAnalyzer

__all__ = [
    'SemgrepAnalyzer',
    'NucleiAnalyzer',
    'BanditAnalyzer',
    'EslintAnalyzer',
    'PHPStanAnalyzer',
]


def get_external_analyzer(tool_name: str):
    """
    Get an external analyzer by name.
    
    Args:
        tool_name: Name of the tool (semgrep, nuclei, bandit, eslint, phpstan)
    
    Returns:
        Analyzer instance or None if not found
    """
    tools_map = {
        'semgrep': SemgrepAnalyzer,
        'nuclei': NucleiAnalyzer,
        'bandit': BanditAnalyzer,
        'eslint': EslintAnalyzer,
        'phpstan': PHPStanAnalyzer,
    }
    
    if tool_name in tools_map:
        return tools_map[tool_name]()
    return None
