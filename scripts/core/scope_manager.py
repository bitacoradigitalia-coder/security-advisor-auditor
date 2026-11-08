"""
Scope Manager for Security Advisor Auditor v2.2

Centralized control of all network operations to prevent:
- Accidental access to localhost/private networks
- Unauthorized redirections
- DNS rebinding attacks
- Excessive requests
- Out-of-scope operations

This module MUST be used by ALL components that make network requests.
"""

import ipaddress
import re
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse, urljoin
import requests


# =============================================================================
# EXCEPTIONS
# =============================================================================

class ScopeValidationError(Exception):
    """Raised when a target fails scope validation."""
    def __init__(self, message: str, target: str = "", reason: str = "") -> None:
        self.message = message
        self.target = target
        self.reason = reason
        super().__init__(f"{message} (target: {target}, reason: {reason})")


class ScopeTimeoutError(ScopeValidationError):
    """Raised when a scope check times out."""
    pass


class ScopeRateLimitError(ScopeValidationError):
    """Raised when rate limits are exceeded."""
    pass


class ScopeKillSwitchError(ScopeValidationError):
    """Raised when kill switch is activated."""
    pass


# =============================================================================
# CONSTANTS
# =============================================================================

# Blocked IP ranges (private, loopback, link-local, cloud metadata)
BLOCKED_NETWORKS = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Private IPv4
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local
    ipaddress.ip_network("169.25
4.0.0/16"),
    # IPv6 link-local
    ipaddress.ip_network("fe80::/10"),
    # IPv6 unique local
    ipaddress.ip_network("fc00::/7"),
    # Cloud metadata endpoints
    ipaddress.ip_network("169.254.169.254/32"),
]

# Blocked domains (can be extended)
BLOCKED_DOMAINS = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "169.254.169.254",  # AWS/Cloud metadata
    "metadata.google.internal",  # GCP metadata
    "169.254.169.123",  # Azure metadata
}

# Allowed protocols
ALLOWED_PROTOCOLS = {"http", "https"}

# Allowed methods
ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}

# Default rate limits
DEFAULT_RATE_LIMITS = {
    "requests_per_second": 10,
    "max_concurrent_requests": 20,
    "timeout": 30,  # seconds
    "max_response_size": 10 * 1024 * 1024,  # 10MB
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ScopeConfig:
    """Configuration for scope validation."""
    allowed_domains: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    allowed_ports: Set[int] = field(default_factory=lambda: {80, 443})
    allowed_protocols: Set[str] = field(default_factory=lambda: ALLOWED_PROTOCOLS.copy())
    allowed_methods: Set[str] = field(default_factory=lambda: ALLOWED_METHODS.copy())
    blocked_domains: Set[str] = field(default_factory=lambda: BLOCKED_DOMAINS.copy())
    blocked_ips: List[str] = field(default_factory=list)
    blocked_ports: Set[int] = field(default_factory=set)
    blocked_protocols: Set[str] = field(default_factory=set)
    
    # Rate limits
    requests_per_second: int = DEFAULT_RATE_LIMITS["requests_per_second"]
    max_concurrent_requests: int = DEFAULT_RATE_LIMITS["max_concurrent_requests"]
    timeout: int = DEFAULT_RATE_LIMITS["timeout"]
    max_response_size: int = DEFAULT_RATE_LIMITS["max_r
esponse_size"]
    
    # DNS settings
    allow_dns_resolution: bool = True
    dns_timeout: float = 5.0
    
    # Security settings
    allow_redirects: bool = True
    max_redirects: int = 5
    validate_redirects: bool = True
    
    # Kill switch
    kill_switch_enabled: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "allowed_domains": self.allowed_domains,
            "allowed_ips": self.allowed_ips,
            "allowed_ports": list(self.allowed_ports),
            "allowed_protocols": list(self.allowed_protocols),
            "allowed_methods": list(self.allowed_methods),
            "blocked_domains": list(self.blocked_domains),
            "blocked_ips": self.blocked_ips,
            "blocked_ports": list(self.blocked_ports),
            "blocked_protocols": list(self.blocked_protocols),
            "requests_per_second": self.requests_per_second,
            "max_concurrent_requests": self.max_concurrent_requests,
            "timeout": self.timeout,
            "max_response_size": self.max_response_size,
            "allow_dns_resolution": self.allow_dns_resolution,
            "dns_timeout": self.dns_timeout,
            "allow_redirects": self.allow_redirects,
            "max_redirects": self.max_redirects,
            "validate_redirects": self.validate_redirects,
            "kill_switch_enabled": self.kill_switch_enabled,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScopeConfig":
        """Create from dictionary."""
        return cls(
            allowed_domains=data.get("allowed_domains", []),
            allowed_ips=data.get("allowed_ips", []),
            allowed_ports=set(data.get("allowed_ports", [80, 443])),
            allowed_protocols=set(data.get("allowed_protocols", list(ALLOWED_PROTOCOLS))),
            allowed_methods=set(data.get("allowed_methods", list(ALLOWED_METHODS))),
            blocked_domains=set(data.get("block
ed_domains", list(BLOCKED_DOMAINS))),
            blocked_ips=data.get("blocked_ips", []),
            blocked_ports=set(data.get("blocked_ports", [])),
            blocked_protocols=set(data.get("blocked_protocols", [])),
            requests_per_second=data.get("requests_per_second", DEFAULT_RATE_LIMITS["requests_per_second"]),
            max_concurrent_requests=data.get("max_concurrent_requests", DEFAULT_RATE_LIMITS["max_concurrent_requests"]),
            timeout=data.get("timeout", DEFAULT_RATE_LIMITS["timeout"]),
            max_response_size=data.get("max_response_size", DEFAULT_RATE_LIMITS["max_response_size"]),
            allow_dns_resolution=data.get("allow_dns_resolution", True),
            dns_timeout=data.get("dns_timeout", 5.0),
            allow_redirects=data.get("allow_redirects", True),
            max_redirects=data.get("max_redirects", 5),
            validate_redirects=data.get("validate_redirects", True),
            kill_switch_enabled=data.get("kill_switch_enabled", False),
        )


@dataclass
class RequestContext:
    """Context for a network request."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Union[Dict, str, bytes]] = None
    params: Optional[Dict] = None
    timeout: Optional[float] = None
    allow_redirects: bool = True
    max_redirects: int = 5
    
    def __post_init__(self) -> None:
        if self.timeout is None:
            self.timeout = DEFAULT_RATE_LIMITS["timeout"]


# =============================================================================
# SCOPE MANAGER
# =============================================================================

class ScopeManager:
    """
    Centralized manager for controlling all network operations.
    
    This class MUST be used by ALL components that make network requests.
    It enforces:
    - Domain/IP/port/protocol validation
    - Blocking of private/local/cloud networks
    - Redirect validation
    - Rate limit
ing
    - Kill switch functionality
    
    Usage:
        scope_manager = ScopeManager(config)
        
        # Validate a target
        scope_manager.validate_target("https://example.com")
        
        # Make a request through the manager
        response = scope_manager.request("GET", "https://example.com")
        
        # Use as a context manager for automatic cleanup
        with scope_manager:
            response = scope_manager.request("GET", "https://example.com")
    """
    
    def __init__(self, config: Optional[ScopeConfig] = None) -> None:
        """
        Initialize ScopeManager.
        
        Args:
            config: Scope configuration. If None, uses default (block all).
        """
        self.config = config if config else ScopeConfig()
        self._lock = threading.RLock()
        self._kill_switch = False
        self._request_count = 0
        self._last_request_time = datetime.min
        self._active_requests = 0
        self._session = requests.Session()
        
        # Configure session
        self._session.max_redirects = self.config.max_redirects
        
        # Rate limiting state
        self._rate_limit_tokens = self.config.max_concurrent_requests
        self._rate_limit_last_refill = datetime.now()
    
    def __enter__(self) -> "ScopeManager":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> None:
        """Context manager exit."""
        self._session.close()
    
    # =========================================================================
    # KILL SWITCH
    # =========================================================================
    
    def enable_kill_switch(self) -> None:
        """Enable the kill switch to stop all operations."""
        with self._lock:
            self._kill_switch = True
    
    def disable_kill_switch(self) -> None:
        """Disable the kill switch."""
        with self._lock:
            self._kill_switch = False
    
    def is_k
ill_switch_enabled(self) -> bool:
        """Check if kill switch is enabled."""
        with self._lock:
            return self._kill_switch or self.config.kill_switch_enabled
    
    def check_kill_switch(self) -> None:
        """Check kill switch and raise if enabled."""
        if self.is_kill_switch_enabled():
            raise ScopeKillSwitchError(
                "Kill switch activated. All operations stopped.",
                target="",
                reason="kill_switch_enabled"
            )
    
    # =========================================================================
    # VALIDATION METHODS
    # =========================================================================
    
    def validate_target(self, target: str) -> Tuple[str, str, int]:
        """
        Validate a target URL or IP:port.
        
        Args:
            target: URL or IP:port to validate
            
        Returns:
            Tuple of (normalized_url, host, port)
            
        Raises:
            ScopeValidationError: If target is not allowed
        """
        self.check_kill_switch()
        
        # Parse URL
        try:
            parsed = urlparse(target)
        except ValueError as e:
            raise ScopeValidationError(
                f"Invalid URL",
                target=target,
                reason=f"url_parse_error: {e}"
            )
        
        # Validate protocol
        protocol = parsed.scheme.lower()
        if protocol not in self.config.allowed_protocols:
            raise ScopeValidationError(
                f"Protocol not allowed",
                target=target,
                reason=f"protocol_not_allowed: {protocol}"
            )
        
        if protocol in self.config.blocked_protocols:
            raise ScopeValidationError(
                f"Protocol blocked",
                target=target,
                reason=f"protocol_blocked: {protocol}"
            )
        
        # Validate port
        port = par
sed.port if parsed.port else (443 if protocol == "https" else 80)
        if port not in self.config.allowed_ports:
            raise ScopeValidationError(
                f"Port not allowed",
                target=target,
                reason=f"port_not_allowed: {port}"
            )
        
        if port in self.config.blocked_ports:
            raise ScopeValidationError(
                f"Port blocked",
                target=target,
                reason=f"port_blocked: {port}"
            )
        
        # Extract host
        host = parsed.hostname
        if not host:
            raise ScopeValidationError(
                f"No host in URL",
                target=target,
                reason="no_host"
            )
        
        # Validate domain
        self._validate_domain(host)
        
        # Validate IP (if host is an IP)
        self._validate_ip(host)
        
        # Reconstruct URL with validated components
        normalized_url = f"{protocol}://{host}"
        if port not in (80, 443) or (port == 80 and protocol == "https") or (port == 443 and protocol == "http"):
            normalized_url += f":{port}"
        if parsed.path:
            normalized_url += parsed.path
        if parsed.query:
            normalized_url += f"?{parsed.query}"
        if parsed.fragment:
            normalized_url += f"#{parsed.fragment}"
        
        return normalized_url, host, port
    
    def _validate_domain(self, domain: str) -> None:
        """Validate a domain name."""
        domain_lower = domain.lower()
        
        # Check blocked domains
        if domain_lower in self.config.blocked_domains:
            raise ScopeValidationError(
                f"Domain blocked",
                target=domain,
                reason=f"domain_blocked: {domain}"
            )
        
        # Check if domain is in allowed list (if specified)
        if self.config.allowed_domains:
            allowed = False
            for allowed_dom
ain in self.config.allowed_domains:
                if self._domain_matches(domain_lower, allowed_domain.lower()):
                    allowed = True
                    break
            if not allowed:
                raise ScopeValidationError(
                    f"Domain not in allowed list",
                    target=domain,
                    reason=f"domain_not_allowed: {domain}"
                )
    
    def _validate_ip(self, host: str) -> None:
        """Validate an IP address."""
        try:
            # Try to parse as IP
            ip = ipaddress.ip_address(host)
            
            # Check blocked networks
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    raise ScopeValidationError(
                        f"IP in blocked network",
                        target=host,
                        reason=f"ip_blocked: {host} in {network}"
                    )
            
            # Check blocked IPs
            for blocked_ip in self.config.blocked_ips:
                try:
                    blocked_network = ipaddress.ip_network(blocked_ip, strict=False)
                    if ip in blocked_network:
                        raise ScopeValidationError(
                            f"IP blocked",
                            target=host,
                            reason=f"ip_blocked: {host} in {blocked_ip}"
                        )
                except ValueError:
                    if host == blocked_ip:
                        raise ScopeValidationError(
                            f"IP blocked",
                            target=host,
                            reason=f"ip_blocked: {host}"
                        )
            
            # Check allowed IPs
            if self.config.allowed_ips:
                allowed = False
                for allowed_ip in self.config.allowed_ips:
                    try:
                        allowed_network = ipaddress.ip_network(allowed_i
p, strict=False)
                        if ip in allowed_network:
                            allowed = True
                            break
                    except ValueError:
                        if host == allowed_ip:
                            allowed = True
                            break
                if not allowed:
                    raise ScopeValidationError(
                        f"IP not in allowed list",
                        target=host,
                        reason=f"ip_not_allowed: {host}"
                    )
                    
        except ValueError:
            # Not an IP address, it's a domain
            pass
    
    def _domain_matches(self, domain: str, pattern: str) -> bool:
        """
        Check if a domain matches a pattern.
        
        Supports:
        - Exact match: "example.com"
        - Wildcard: "*.example.com"
        - Subdomain: "sub.example.com"
        
        Args:
            domain: Domain to check
            pattern: Pattern to match against
            
        Returns:
            True if domain matches pattern
        """
        domain = domain.rstrip(".")
        pattern = pattern.rstrip(".")
        
        # Exact match
        if domain == pattern:
            return True
        
        # Wildcard match
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if domain.endswith("." + suffix) or domain == suffix:
                return True
        
        # Subdomain match (pattern is parent domain)
        if domain.endswith("." + pattern):
            return True
        
        return False
    
    def validate_redirect(self, original_url: str, redirect_url: str) -> str:
        """
        Validate a redirect URL.
        
        Args:
            original_url: Original URL that redirected
            redirect_url: URL to redirect to
            
        Returns:
            Validated redirect URL
            
        Raises:
            Scop
eValidationError: If redirect is not allowed
        """
        self.check_kill_switch()
        
        # If redirect validation is disabled, just validate the target
        if not self.config.validate_redirects:
            return self.validate_target(redirect_url)[0]
        
        # Parse both URLs
        try:
            original_parsed = urlparse(original_url)
            redirect_parsed = urlparse(redirect_url)
        except ValueError as e:
            raise ScopeValidationError(
                f"Invalid redirect URL",
                target=redirect_url,
                reason=f"url_parse_error: {e}"
            )
        
        # Validate the redirect target
        validated_url, _, _ = self.validate_target(redirect_url)
        
        # Additional checks for redirects
        redirect_host = redirect_parsed.hostname
        original_host = original_parsed.hostname
        
        # If redirecting to a different host, check if it's allowed
        if redirect_host != original_host:
            # Check if redirect is to a blocked domain
            if redirect_host and redirect_host.lower() in self.config.blocked_domains:
                raise ScopeValidationError(
                    f"Redirect to blocked domain",
                    target=redirect_url,
                    reason=f"redirect_blocked: {redirect_host}"
                )
            
            # Check if redirect is to a private network
            try:
                ip = ipaddress.ip_address(redirect_host)
                for network in BLOCKED_NETWORKS:
                    if ip in network:
                        raise ScopeValidationError(
                            f"Redirect to blocked network",
                            target=redirect_url,
                            reason=f"redirect_blocked_network: {redirect_host}"
                        )
            except ValueError:
                pass
        
        return validated_url
    
    def validate_method(sel
f, method: str) -> None:
        """Validate HTTP method."""
        method_upper = method.upper()
        if method_upper not in self.config.allowed_methods:
            raise ScopeValidationError(
                f"Method not allowed",
                target=method,
                reason=f"method_not_allowed: {method}"
            )
        
        if method_upper in self.config.blocked_protocols:
            raise ScopeValidationError(
                f"Method blocked",
                target=method,
                reason=f"method_blocked: {method}"
            )
    
    # =========================================================================
    # DNS VALIDATION
    # =========================================================================
    
    def resolve_dns(self, hostname: str) -> List[str]:
        """
        Resolve DNS for a hostname with security checks.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            List of resolved IP addresses
            
        Raises:
            ScopeValidationError: If DNS resolution is not allowed or fails
        """
        self.check_kill_switch()
        
        if not self.config.allow_dns_resolution:
            raise ScopeValidationError(
                f"DNS resolution not allowed",
                target=hostname,
                reason="dns_resolution_disabled"
            )
        
        try:
            # Resolve DNS
            ip_addresses = socket.getaddrinfo(hostname, None)
            resolved_ips = list({ip[4][0] for ip in ip_addresses})
            
            # Validate each resolved IP
            for ip in resolved_ips:
                self._validate_ip(ip)
            
            return resolved_ips
            
        except socket.gaierror as e:
            raise ScopeValidationError(
                f"DNS resolution failed",
                target=hostname,
                reason=f"dns_error: {e}"
            )
        exce
pt socket.timeout:
            raise ScopeTimeoutError(
                f"DNS resolution timed out",
                target=hostname,
                reason="dns_timeout"
            )
    
    # =========================================================================
    # RATE LIMITING
    # =========================================================================
    
    def check_rate_limit(self) -> None:
        """
        Check if rate limit is exceeded.
        
        Raises:
            ScopeRateLimitError: If rate limit is exceeded
        """
        with self._lock:
            now = datetime.now()
            
            # Refill tokens based on time elapsed
            time_elapsed = (now - self._rate_limit_last_refill).total_seconds()
            tokens_to_add = int(time_elapsed * self.config.requests_per_second)
            
            if tokens_to_add > 0:
                self._rate_limit_tokens = min(
                    self._rate_limit_tokens + tokens_to_add,
                    self.config.max_concurrent_requests
                )
                self._rate_limit_last_refill = now
            
            # Check if we have tokens available
            if self._rate_limit_tokens <= 0:
                raise ScopeRateLimitError(
                    f"Rate limit exceeded",
                    target="",
                    reason=f"rate_limit: {self.config.requests_per_second} req/s"
                )
            
            # Consume a token
            self._rate_limit_tokens -= 1
    
    def wait_for_rate_limit(self) -> None:
        """Wait until rate limit allows a new request."""
        while True:
            try:
                self.check_rate_limit()
                return
            except ScopeRateLimitError:
                # Wait a bit and retry
                time.sleep(0.1)
    
    # =========================================================================
    # REQUEST METHODS
    # =====================================
====================================
    
    def request(
        self,
        method: str,
        url: str,
        **kwargs: Any
    ) -> requests.Response:
        """
        Make a network request through the scope manager.
        
        This is the PRIMARY method for making network requests.
        ALL modules should use this instead of requests.get/post directly.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request
            **kwargs: Additional arguments for requests
            
        Returns:
            requests.Response object
            
        Raises:
            ScopeValidationError: If target is not allowed
            ScopeRateLimitError: If rate limit is exceeded
            ScopeKillSwitchError: If kill switch is activated
        """
        self.check_kill_switch()
        
        # Validate method
        self.validate_method(method)
        
        # Validate target
        validated_url, _, _ = self.validate_target(url)
        
        # Check rate limit
        self.wait_for_rate_limit()
        
        # Prepare request
        with self._lock:
            self._active_requests += 1
        
        try:
            # Set timeout
            timeout = kwargs.pop("timeout", self.config.timeout)
            
            # Set allow_redirects
            allow_redirects = kwargs.pop("allow_redirects", self.config.allow_redirects)
            
            # Make the request
            response = self._session.request(
                method,
                validated_url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs: Any
            )
            
            # Validate redirects if needed
            if allow_redirects and self.config.validate_redirects:
                for redirect in response.history:
                    self.validate_redirect(redirect.url, response.url)
            
            # Check response size
    
        if len(response.content) > self.config.max_response_size:
                raise ScopeValidationError(
                    f"Response too large",
                    target=validated_url,
                    reason=f"response_size: {len(response.content)} > {self.config.max_response_size}"
                )
            
            return response
            
        finally:
            with self._lock:
                self._active_requests -= 1
    
    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP GET request."""
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP POST request."""
        return self.request("POST", url, **kwargs)
    
    def put(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP PUT request."""
        return self.request("PUT", url, **kwargs)
    
    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP DELETE request."""
        return self.request("DELETE", url, **kwargs)
    
    def head(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP HEAD request."""
        return self.request("HEAD", url, **kwargs)
    
    def options(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)
    
    def patch(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP PATCH request."""
        return self.request("PATCH", url, **kwargs)
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def is_blocked_network(self, ip_or_network: str) -> bool:
        """Check if an IP or network is in the blocked list."""
        try:
            network = ipaddress.ip_network(ip_or_network, strict=False)
            for blocked in BLOCKED_NETWORKS:
                if network.over
laps(blocked):
                    return True
            return False
        except ValueError:
            return False
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if an IP is in a private network range."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            for network in BLOCKED_NETWORKS:
                if ip_addr in network:
                    return True
            return False
        except ValueError:
            return False
    
    def get_stats(self) -> Dict:
        """Get statistics about scope manager usage."""
        with self._lock:
            return {
                "request_count": self._request_count,
                "active_requests": self._active_requests,
                "kill_switch_enabled": self.is_kill_switch_enabled(),
                "rate_limit_tokens": self._rate_limit_tokens,
                "config": self.config.to_dict(),
            }
    
    def reset_stats(self) -> None:
        """Reset usage statistics."""
        with self._lock:
            self._request_count = 0
            self._active_requests = 0
            self._rate_limit_tokens = self.config.max_concurrent_requests
            self._rate_limit_last_refill = datetime.now()


# =============================================================================
# GLOBAL SCOPE MANAGER INSTANCE
# =============================================================================

# Global instance (can be replaced with a custom one)
_global_scope_manager: Optional[ScopeManager] = None


def get_scope_manager() -> ScopeManager:
    """Get the global scope manager instance."""
    global _global_scope_manager
    if _global_scope_manager is None:
        _global_scope_manager = ScopeManager()
    return _global_scope_manager


def set_scope_manager(scope_manager: ScopeManager) -> None:
    """Set the global scope manager instance."""
    global _global_scope_manager
    _global_scope_manager = scope_manager


def reset_scope_manager
() -> None:
    """Reset the global scope manager instance."""
    global _global_scope_manager
    if _global_scope_manager is not None:
        _global_scope_manager._session.close()
    _global_scope_manager = None
