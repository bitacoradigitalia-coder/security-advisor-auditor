"""
Engagement Manager for Security Advisor Auditor v2.2

Manages authorization for active security operations (pentesting, scanning, etc.).

This module ensures that:
- All active operations have explicit authorization
- Authorization is checked before EVERY operation
- Wildcard patterns are matched safely
- Expired authorizations are rejected
- Authorizations are auditable

Usage:
    engagement_manager = EngagementManager()
    
    # Create an engagement
    engagement = engagement_manager.create_engagement(
        engagement_id="eng-001",
        owner="user@example.com",
        targets=["example.com", "*.example.com"],
        start_time=datetime.now(),
        end_time=datetime.now() + timedelta(hours=24),
        allowed_types=["scan", "fuzz", "exploit"],
        evidence="Signed authorization from client"
    )
    
    # Validate an operation
    engagement_manager.validate(
        engagement_id="eng-001",
        target="https://api.example.com",
        operation_type="scan"
    )
"""

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse

from .scope_manager import ScopeManager, get_scope_manager


# =============================================================================
# EXCEPTIONS
# =============================================================================

class AuthorizationError(Exception):
    """Raised when authorization fails."""
    def __init__(self, message: str, engagement_id: str = "", target: str = "", 
                 operation_type: str = "", reason: str = ""):
        self.message = message
        self.engagement_id = engagement_id
        self.target = target
        self.operation_type = operation_type
        self.reason = reason
        super().__init__(
            f"{message} | engagement={engagement_id} | 
target={target} | "
            f"operation={operation_type} | reason={reason}"
        )


class EngagementNotFoundError(AuthorizationError):
    """Raised when an engagement is not found."""
    pass


class EngagementExpiredError(AuthorizationError):
    """Raised when an engagement has expired."""
    pass


class EngagementInvalidError(AuthorizationError):
    """Raised when an engagement is invalid."""
    pass


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Engagement:
    """
    Represents an authorization engagement for active security operations.
    
    Each engagement must include:
    - identifier: Unique engagement ID
    - owner: Responsible person/email
    - targets: Authorized domains/IPs
    - start_time: When the engagement starts
    - end_time: When the engagement ends
    - allowed_types: Types of operations allowed
    - evidence: Proof of authorization
    """
    engagement_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    owner: str = ""
    owner_email: Optional[str] = None
    targets: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    allowed_ports: Set[int] = field(default_factory=lambda: {80, 443})
    allowed_types: Set[str] = field(default_factory=lambda: {"scan", "fuzz", "exploit"})
    blocked_targets: List[str] = field(default_factory=list)
    blocked_types: Set[str] = field(default_factory=set)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=24))
    timezone: str = "UTC"
    rate_limits: Dict[str, Any] = field(default_factory=dict)
    restrictions: List[str] = field(default_factory=list)
    evidence: str = ""
    evidence_has
h: Optional[str] = None
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True
    
    def __post_init__(self) -> None:
        # Ensure timezone-aware datetimes
        if self.start_time.tzinfo is None:
            self.start_time = self.start_time.replace(tzinfo=timezone.utc)
        if self.end_time.tzinfo is None:
            self.end_time = self.end_time.replace(tzinfo=timezone.utc)
        if self.created_at.tzinfo is None:
            self.created_at = self.created_at.replace(tzinfo=timezone.utc)
        if self.updated_at.tzinfo is None:
            self.updated_at = self.updated_at.replace(tzinfo=timezone.utc)
        
        # Calculate evidence hash if evidence is provided
        if self.evidence and not self.evidence_hash:
            self.evidence_hash = self._calculate_hash(self.evidence)
    
    def _calculate_hash(self, data: str) -> str:
        """Calculate SHA256 hash of data."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def is_valid(self) -> bool:
        """Check if the engagement is valid."""
        now = datetime.now(timezone.utc)
        return (
            self.is_active and
            now >= self.start_time and
            now <= self.end_time and
            bool(self.owner) and
            (bool(self.targets) or bool(self.allowed_domains) or bool(self.allowed_ips))
        )
    
    def is_expired(self) -> bool:
        """Check if the engagement has expired."""
        now = datetime.now(timezone.utc)
        return now > self.end_time
    
    def time_remaining(self) -> timedelta:
        """Get remaining time for the engagement."""
        now = datetime.now(timezone.utc)
        if now > self.end_time:
            return timedelta(seconds=0)
        return self.end_time - now
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
 
           "engagement_id": self.engagement_id,
            "name": self.name,
            "owner": self.owner,
            "owner_email": self.owner_email,
            "targets": self.targets,
            "allowed_domains": self.allowed_domains,
            "allowed_ips": self.allowed_ips,
            "allowed_ports": list(self.allowed_ports),
            "allowed_types": list(self.allowed_types),
            "blocked_targets": self.blocked_targets,
            "blocked_types": list(self.blocked_types),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "timezone": self.timezone,
            "rate_limits": self.rate_limits,
            "restrictions": self.restrictions,
            "evidence": self.evidence,
            "evidence_hash": self.evidence_hash,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "is_active": self.is_active,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Engagement":
        """Create from dictionary."""
        return cls(
            engagement_id=data.get("engagement_id", str(uuid.uuid4())),
            name=data.get("name", ""),
            owner=data.get("owner", ""),
            owner_email=data.get("owner_email"),
            targets=data.get("targets", []),
            allowed_domains=data.get("allowed_domains", []),
            allowed_ips=data.get("allowed_ips", []),
            allowed_ports=set(data.get("allowed_ports", [80, 443])),
            allowed_types=set(data.get("allowed_types", ["scan", "fuzz", "exploit"])),
            blocked_targets=data.get("blocked_targets", []),
            blocked_types=set(data.get("blocked_types", [])),
            start_time=datetime.fromisoformat(data.get("start_time", datetime.now(timezone.utc).isoformat())),
            end_time=datetime.fromisoformat(data.get("end_time", (datetime.now(
timezone.utc) + timedelta(hours=24)).isoformat())),
            timezone=data.get("timezone", "UTC"),
            rate_limits=data.get("rate_limits", {}),
            restrictions=data.get("restrictions", []),
            evidence=data.get("evidence", ""),
            evidence_hash=data.get("evidence_hash"),
            notes=data.get("notes", ""),
            created_at=datetime.fromisoformat(data.get("created_at", datetime.now(timezone.utc).isoformat())),
            updated_at=datetime.fromisoformat(data.get("updated_at", datetime.now(timezone.utc).isoformat())),
            is_active=data.get("is_active", True),
        )


# =============================================================================
# ENGAGEMENT MANAGER
# =============================================================================

class EngagementManager:
    """
    Manages engagements for active security operations.
    
    This class ensures that:
    - All active operations have explicit authorization
    - Authorization is checked before EVERY operation
    - Wildcard patterns are matched safely
    - Expired engagements are rejected
    - Engagements are auditable
    
    Usage:
        engagement_manager = EngagementManager()
        
        # Create an engagement
        engagement = engagement_manager.create_engagement(
            owner="user@example.com",
            targets=["example.com"],
            end_time=datetime.now() + timedelta(hours=24)
        )
        
        # Validate an operation
        engagement_manager.validate(
            engagement_id=engagement.engagement_id,
            target="https://example.com/api",
            operation_type="scan"
        )
    """
    
    def __init__(self, storage_path: Optional[Union[str, Path]] = None) -> None:
        """
        Initialize EngagementManager.
        
        Args:
            storage_path: Path to store engagements (JSON file)
        """
        self.storage_path = Path(storage_path) if storage_path else None

        self._engagements: Dict[str, Engagement] = {}
        self._scope_manager: Optional[ScopeManager] = None
        
        # Load engagements from storage if path is provided
        if self.storage_path and self.storage_path.exists():
            self._load_engagements()
    
    @property
    def scope_manager(self) -> ScopeManager:
        """Get the scope manager instance."""
        if self._scope_manager is None:
            from .scope_manager import get_scope_manager
            self._scope_manager = get_scope_manager()
        return self._scope_manager
    
    @scope_manager.setter
    def scope_manager(self, value: ScopeManager) -> None:
        """Set the scope manager instance."""
        self._scope_manager = value
    
    # =========================================================================
    # ENGAGEMENT MANAGEMENT
    # =========================================================================
    
    def create_engagement(
        self,
        owner: str,
        targets: Optional[List[str]] = None,
        allowed_types: Optional[Set[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        evidence: str = "",
        name: str = "",
        owner_email: Optional[str] = None,
        allowed_domains: Optional[List[str]] = None,
        allowed_ips: Optional[List[str]] = None,
        allowed_ports: Optional[Set[int]] = None,
        blocked_targets: Optional[List[str]] = None,
        blocked_types: Optional[Set[str]] = None,
        rate_limits: Optional[Dict[str, Any]] = None,
        restrictions: Optional[List[str]] = None,
        notes: str = "",
    ) -> Engagement:
        """
        Create a new engagement.
        
        Args:
            owner: Owner of the engagement (required)
            targets: List of authorized targets (domains/IPs)
            allowed_types: Set of allowed operation types
            start_time: Start time (default: now)
            end
_time: End time (default: now + 24 hours)
            evidence: Proof of authorization
            name: Engagement name
            owner_email: Owner email
            allowed_domains: Additional allowed domains
            allowed_ips: Allowed IPs
            allowed_ports: Allowed ports
            blocked_targets: Blocked targets
            blocked_types: Blocked operation types
            rate_limits: Rate limits
            restrictions: Additional restrictions
            notes: Notes
            
        Returns:
            Engagement object
        """
        if not owner:
            raise ValueError("Owner is required")
        
        if not targets and not allowed_domains and not allowed_ips:
            raise ValueError("At least one target, domain, or IP is required")
        
        engagement = Engagement(
            name=name,
            owner=owner,
            owner_email=owner_email,
            targets=targets or [],
            allowed_domains=allowed_domains or [],
            allowed_ips=allowed_ips or [],
            allowed_ports=allowed_ports or {80, 443},
            allowed_types=allowed_types or {"scan", "fuzz", "exploit"},
            blocked_targets=blocked_targets or [],
            blocked_types=blocked_types or set(),
            start_time=start_time or datetime.now(timezone.utc),
            end_time=end_time or (datetime.now(timezone.utc) + timedelta(hours=24)),
            rate_limits=rate_limits or {},
            restrictions=restrictions or [],
            evidence=evidence,
            notes=notes,
        )
        
        # Store the engagement
        self._engagements[engagement.engagement_id] = engagement
        
        # Save to storage if path is configured
        if self.storage_path:
            self._save_engagements()
        
        return engagement
    
    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        """Get an engagement by ID."""
        return self._engagement
s.get(engagement_id)
    
    def list_engagements(self) -> List[Engagement]:
        """List all engagements."""
        return list(self._engagements.values())
    
    def update_engagement(self, engagement_id: str, **kwargs: Any) -> Optional[Engagement]:
        """Update an engagement."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            return None
        
        # Update fields
        for key, value in kwargs.items():
            if hasattr(engagement, key):
                setattr(engagement, key, value)
        
        # Update timestamp
        engagement.updated_at = datetime.now(timezone.utc)
        
        # Save to storage if path is configured
        if self.storage_path:
            self._save_engagements()
        
        return engagement
    
    def delete_engagement(self, engagement_id: str) -> bool:
        """Delete an engagement."""
        if engagement_id in self._engagements:
            del self._engagements[engagement_id]
            
            # Save to storage if path is configured
            if self.storage_path:
                self._save_engagements()
            
            return True
        return False
    
    def deactivate_engagement(self, engagement_id: str) -> bool:
        """Deactivate an engagement."""
        engagement = self._engagements.get(engagement_id)
        if engagement:
            engagement.is_active = False
            engagement.updated_at = datetime.now(timezone.utc)
            
            # Save to storage if path is configured
            if self.storage_path:
                self._save_engagements()
            
            return True
        return False
    
    # =========================================================================
    # VALIDATION METHODS
    # =========================================================================
    
    def validate(
        self,
        engagement_id: str,
        target: str,
        operation_
type: str = "scan",
        method: str = "GET",
        validate_scope: bool = True,
    ) -> Engagement:
        """
        Validate an operation against an engagement.
        
        This MUST be called before EVERY active operation.
        
        Args:
            engagement_id: Engagement ID
            target: Target URL or IP
            operation_type: Type of operation (scan, fuzz, exploit, etc.)
            method: HTTP method
            validate_scope: Whether to also validate with ScopeManager
            
        Returns:
            Engagement object if valid
            
        Raises:
            EngagementNotFoundError: If engagement is not found
            EngagementExpiredError: If engagement has expired
            EngagementInvalidError: If engagement is invalid
            AuthorizationError: If operation is not authorized
        """
        # Get engagement
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise EngagementNotFoundError(
                "Engagement not found",
                engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason="engagement_not_found"
            )
        
        # Check if engagement is valid
        if not engagement.is_valid():
            raise EngagementInvalidError(
                "Engagement is invalid",
                engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason="engagement_invalid"
            )
        
        # Check if engagement has expired
        if engagement.is_expired():
            raise EngagementExpiredError(
                "Engagement has expired",
                engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason=f"expired_at: {engagement.end_time.isoformat()}"
            )
        
       
 # Check operation type
        if operation_type not in engagement.allowed_types:
            raise AuthorizationError(
                "Operation type not allowed",
                engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason=f"operation_not_allowed: {operation_type}"
            )
        
        if operation_type in engagement.blocked_types:
            raise AuthorizationError(
                "Operation type blocked",
                engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason=f"operation_blocked: {operation_type}"
            )
        
        # Parse target URL
        try:
            parsed = urlparse(target)
            target_host = parsed.hostname or target
            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            target_host = target
            target_port = 80
        
        # Check if target is in allowed list
        if not self._is_target_allowed(engagement, target, target_host, target_port):
            raise AuthorizationError(
                "Target not allowed",
                engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason=f"target_not_allowed: {target}"
            )
        
        # Check if target is in blocked list
        if self._is_target_blocked(engagement, target, target_host, target_port):
            raise AuthorizationError(
                "Target blocked",
                engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason=f"target_blocked: {target}"
            )
        
        # Check port
        if target_port not in engagement.allowed_ports:
            raise AuthorizationError(
                "Port not allowed",
            
    engagement_id=engagement_id,
                target=target,
                operation_type=operation_type,
                reason=f"port_not_allowed: {target_port}"
            )
        
        # Validate with ScopeManager if requested
        if validate_scope:
            self.scope_manager.validate_target(target)
            self.scope_manager.validate_method(method)
        
        return engagement
    
    def _is_target_allowed(
        self,
        engagement: Engagement,
        target: str,
        host: str,
        port: int,
    ) -> bool:
        """Check if a target is allowed by the engagement."""
        # Check explicit targets
        for allowed_target in engagement.targets:
            if self._target_matches(target, host, port, allowed_target):
                return True
        
        # Check allowed domains
        for allowed_domain in engagement.allowed_domains:
            if self._domain_matches(host, allowed_domain):
                return True
        
        # Check allowed IPs
        for allowed_ip in engagement.allowed_ips:
            if self._ip_matches(host, allowed_ip):
                return True
        
        # If no explicit targets and no allowed lists, allow all (not recommended)
        if not engagement.targets and not engagement.allowed_domains and not engagement.allowed_ips:
            return True
        
        return False
    
    def _is_target_blocked(
        self,
        engagement: Engagement,
        target: str,
        host: str,
        port: int,
    ) -> bool:
        """Check if a target is blocked by the engagement."""
        for blocked_target in engagement.blocked_targets:
            if self._target_matches(target, host, port, blocked_target):
                return True
        return False
    
    def _target_matches(
        self,
        target: str,
        host: str,
        port: int,
        pattern: str,
    ) -> bool:
        """
        Check if a target matches a patte
rn.
        
        Supports:
        - Full URL: "https://example.com:8080/path"
        - Domain: "example.com"
        - Wildcard domain: "*.example.com"
        - IP: "192.168.1.1"
        - IP with port: "192.168.1.1:8080"
        - IP range: "192.168.1.0/24"
        """
        # Parse pattern
        try:
            pattern_parsed = urlparse(pattern)
            pattern_host = pattern_parsed.hostname or pattern
            pattern_port = pattern_parsed.port
        except ValueError:
            pattern_host = pattern
            pattern_port = None
        
        # Check if pattern is an IP range
        try:
            import ipaddress
            network = ipaddress.ip_network(pattern_host, strict=False)
            try:
                ip = ipaddress.ip_address(host)
                if ip in network:
                    # Check port if specified
                    if pattern_port is None or port == pattern_port:
                        return True
            except ValueError:
                pass
        except (ValueError, ImportError):
            pass
        
        # Check domain matching
        if self._domain_matches(host, pattern_host):
            # Check port if specified
            if pattern_port is None or port == pattern_port:
                return True
        
        # Check exact match
        if target == pattern:
            return True
        
        # Check if pattern is a full URL and matches
        if pattern.startswith(("http://", "https://")):
            if target.startswith(pattern):
                return True
        
        return False
    
    def _domain_matches(self, domain: str, pattern: str) -> bool:
        """
        Check if a domain matches a pattern.
        
        Supports:
        - Exact match: "example.com"
        - Wildcard: "*.example.com"
        - Subdomain: "sub.example.com"
        """
        domain = domain.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        
 
       # Exact match
        if domain == pattern:
            return True
        
        # Wildcard match (safe pattern matching)
        if pattern.startswith("*."):
            # Escape special regex characters in domain parts
            suffix = pattern[2:]
            # Use endswith for safe wildcard matching
            if domain.endswith("." + suffix) or domain == suffix:
                return True
        
        # Subdomain match
        if domain.endswith("." + pattern):
            return True
        
        return False
    
    def _ip_matches(self, ip: str, pattern: str) -> bool:
        """Check if an IP matches a pattern."""
        try:
            import ipaddress
            ip_addr = ipaddress.ip_address(ip)
            
            # Check if pattern is an IP
            try:
                pattern_addr = ipaddress.ip_address(pattern)
                return ip_addr == pattern_addr
            except ValueError:
                pass
            
            # Check if pattern is a network
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                return ip_addr in network
            except ValueError:
                pass
        except (ValueError, ImportError):
            pass
        
        return False
    
    # =========================================================================
    # STORAGE METHODS
    # =========================================================================
    
    def _load_engagements(self) -> None:
        """Load engagements from storage file."""
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for engagement_data in data.get("engagements", []):
                    engagement = Engagement.from_dict(engagement_data)
                    self._engagements[engagement.engagement_id] = engagement
        except (json.JSONDecodeError, IOError, OSError):
            # If file d
oesn't exist or is invalid, start with empty engagements
            pass
    
    def _save_engagements(self) -> None:
        """Save engagements to storage file."""
        if not self.storage_path:
            return
        
        try:
            # Ensure parent directory exists
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save engagements
            data = {
                "engagements": [e.to_dict() for e in self._engagements.values()],
                "version": "2.2",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            
            # Write with restrictive permissions (600)
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Set file permissions (if possible)
            try:
                os.chmod(self.storage_path, 0o600)
            except (OSError, AttributeError):
                pass
                
        except (IOError, OSError) as e:
            # Log error but don't fail
            pass


# =============================================================================
# GLOBAL ENGAGEMENT MANAGER INSTANCE
# =============================================================================

# Global instance (can be replaced with a custom one)
_global_engagement_manager: Optional[EngagementManager] = None


def get_engagement_manager() -> EngagementManager:
    """Get the global engagement manager instance."""
    global _global_engagement_manager
    if _global_engagement_manager is None:
        _global_engagement_manager = EngagementManager()
    return _global_engagement_manager


def set_engagement_manager(engagement_manager: EngagementManager) -> None:
    """Set the global engagement manager instance."""
    global _global_engagement_manager
    _global_engagement_manager = engagement_manager


def reset_engagement_manager() -> None:

    """Reset the global engagement manager instance."""
    global _global_engagement_manager
    _global_engagement_manager = None
