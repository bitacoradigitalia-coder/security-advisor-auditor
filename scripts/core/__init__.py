"""
Core Module for Security Advisor Auditor v2.2
Centralized components for security, scope management, authorization,
evidence collection, and verification.

This module contains:
- scope_manager.py: Centralized control of network operations
- engagement_manager.py: Authorization and engagement management
- evidence_engine.py: Evidence collection and normalization
- verification_engine.py: Finding verification and false positive reduction
"""

from .scope_manager import ScopeManager, ScopeValidationError, ScopeConfig
from .engagement_manager import EngagementManager, Engagement, AuthorizationError
from .evidence_engine import (
    EvidenceEngine, Evidence, EvidenceType, 
    ConfidenceLevel, VerificationStatus, Finding
)
from .verification_engine import (
    VerificationEngine, VerificationMethod, VerificationRule
)

__all__ = [
    # Scope Manager
    'ScopeManager', 'ScopeValidationError', 'ScopeConfig',
    # Engagement Manager
    'EngagementManager', 'Engagement', 'AuthorizationError',
    # Evidence Engine
    'EvidenceEngine', 'Evidence', 'EvidenceType',
    'ConfidenceLevel', 'VerificationStatus', 'Finding',
    # Verification Engine
    'VerificationEngine', 'VerificationMethod', 'VerificationRule'
]
__version__ = "2.2.0"
