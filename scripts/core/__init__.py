"""
Core Module for Security Advisor Auditor v2.2
Centralized components for security, scope management, and authorization.

This module contains:
- scope_manager.py: Centralized control of network operations
- engagement_manager.py: Authorization and engagement management
- evidence_engine.py: Evidence collection and validation
- verification_engine.py: Finding verification
"""

from .scope_manager import ScopeManager, ScopeValidationError, ScopeConfig
from .engagement_manager import EngagementManager, Engagement, AuthorizationError

__all__ = ['ScopeManager', 'ScopeValidationError', 'ScopeConfig', 
           'EngagementManager', 'Engagement', 'AuthorizationError']
__version__ = "2.2.0"
