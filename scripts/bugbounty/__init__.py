"""
Bug Bounty Module for Security Advisor Auditor v3.0
Program management, platform integration, and report generation.
"""

from .manager import BugBountyManager
from .platforms import HackerOneIntegration, BugcrowdIntegration
from .prioritizer import FindingPrioritizer

__all__ = ['BugBountyManager', 'HackerOneIntegration', 'BugcrowdIntegration', 'FindingPrioritizer']
__version__ = "3.0.0"
