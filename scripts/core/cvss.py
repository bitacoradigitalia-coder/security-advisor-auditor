"""
CVSS 3.1 Calculator for Security Advisor Auditor v2.3
Calculates CVSS (Common Vulnerability Scoring System) v3.1 base scores.

This module implements the CVSS v3.1 specification for calculating base scores.
Reference: https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf

CVSS Vector Format: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any, Tuple
from enum import Enum


class AttackVector(Enum):
    """Attack Vector (AV) - How the vulnerability is exploited"""
    NETWORK = ("N", 0.85, "Network")
    ADJACENT = ("A", 0.62, "Adjacent Network")
    LOCAL = ("L", 0.55, "Local")
    PHYSICAL = ("P", 0.2, "Physical")
    
    @property
    def code(self) -> str:
        return self._value_[0]
    
    @property
    def numeric_value(self) -> float:
        return self._value_[1]
    
    @property
    def description(self) -> str:
        return self._value_[2]
    
    @classmethod
    def from_code(cls, code: str) -> 'AttackVector':
        """Get AttackVector from code (N, A, L, P)"""
        code = code.upper()
        for av in cls:
            if av.code == code:
                return av
        raise ValueError(f"Invalid AttackVector code: {code}")


class AttackComplexity(Enum):
    """Attack Complexity (AC) - Conditions beyond the attacker's control"""
    LOW = ("L", 0.77, "Low")
    HIGH = ("H", 0.44, "High")
    
    @property
    def code(self) -> str:
        return self._value_[0]
    
    @property
    def numeric_value(self) -> float:
        return self._value_[1]
    
    @property
    def description(self) -> str:
        return self._value_[2]
    
    @classmethod
    def from_code(cls, code: str) -> 'AttackComplexity':
        """Get AttackComplexity from code (L, H)"""
        code = code.upper()
        for ac in cls:
            if ac.code == code:
                return ac
        raise ValueError(f"Invalid AttackComplexity code: {code}")


class PrivilegesRequired(Enum):
    """Privileges Required (PR) - Level of privileges needed to exploit"""
    NONE = ("N", 0.85, "None")
    LOW = ("L", 0.62, "Low")
    HIGH = ("H", 0.27, "High")
    
    @property
    def code(self) -> str:
        return self._value_[0]
    
    @property
    def numeric_value(self) -> float:
        return self._value_[1]
    
    @property
    def description(self) -> str:
        return self._value_[2]
    
    @classmethod
    def from_code(cls, code: str) -> 'PrivilegesRequired':
        """Get PrivilegesRequired from code (N, L, H)"""
        code = code.upper()
        for pr in cls:
            if pr.code == code:
                return pr
        raise ValueError(f"Invalid PrivilegesRequired code: {code}")


class UserInteraction(Enum):
    """User Interaction (UI) - Whether user interaction is required"""
    NONE = ("N", 0.85, "None")
    REQUIRED = ("R", 0.62, "Required")
    
    @property
    def code(self) -> str:
        return self._value_[0]
    
    @property
    def numeric_value(self) -> float:
        return self._value_[1]
    
    @property
    def description(self) -> str:
        return self._value_[2]
    
    @classmethod
    def from_code(cls, code: str) -> 'UserInteraction':
        """Get UserInteraction from code (N, R)"""
        code = code.upper()
        for ui in cls:
            if ui.code == code:
                return ui
        raise ValueError(f"Invalid UserInteraction code: {code}")


class Scope(Enum):
    """Scope (S) - Whether the vulnerability affects components beyond the vulnerable one"""
    UNCHANGED = ("U", "Unchanged")
    CHANGED = ("C", "Changed")
    
    @property
    def code(self) -> str:
        return self._value_[0]
    
    @property
    def description(self) -> str:
        return self._value_[1]
    
    @classmethod
    def from_code(cls, code: str) -> 'Scope':
        """Get Scope from code (U, C)"""
        code = code.upper()
        for s in cls:
            if s.code == code:
                return s
        raise ValueError(f"Invalid Scope code: {code}")


class ImpactMetric(Enum):
    """Impact Metrics (C, I, A) - Confidentiality, Integrity, Availability"""
    NONE = ("N", 0.0, "None")
    LOW = ("L", 0.22, "Low")
    HIGH = ("H", 0.56, "High")
    
    @property
    def code(self) -> str:
        return self._value_[0]
    
    @property
    def numeric_value(self) -> float:
        return self._value_[1]
    
    @property
    def description(self) -> str:
        return self._value_[2]
    
    @classmethod
    def from_code(cls, code: str) -> 'ImpactMetric':
        """Get ImpactMetric from code (N, L, H)"""
        code = code.upper()
        for im in cls:
            if im.code == code:
                return im
        raise ValueError(f"Invalid ImpactMetric code: {code}")


@dataclass
class CVSSVector:
    """
    CVSS v3.1 Vector representation.
    
    Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    """
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: ImpactMetric
    integrity: ImpactMetric
    availability: ImpactMetric
    
    def to_vector_string(self) -> str:
        """Convert to CVSS vector string format."""
        return (f"CVSS:3.1/AV:{self.attack_vector.code}/"
                f"AC:{self.attack_complexity.code}/"
                f"PR:{self.privileges_required.code}/"
                f"UI:{self.user_interaction.code}/"
                f"S:{self.scope.code}/"
                f"C:{self.confidentiality.code}/"
                f"I:{self.integrity.code}/"
                f"A:{self.availability.code}")
    
    @classmethod
    def from_vector_string(cls, vector: str) -> 'CVSSVector':
        """
        Parse CVSS vector string.
        
        Args:
            vector: CVSS vector string (e.g., "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
            
        Returns:
            CVSSVector instance
        """
        # Remove CVSS:3.1/ prefix if present
        vector = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
        
        # Parse components
        parts = vector.split("/")
        components = {}
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                components[key.upper()] = value.upper()
        
        # Extract values
        av = AttackVector.from_code(components.get("AV", "N"))
        ac = AttackComplexity.from_code(components.get("AC", "L"))
        pr = PrivilegesRequired.from_code(components.get("PR", "N"))
        ui = UserInteraction.from_code(components.get("UI", "N"))
        s = Scope.from_code(components.get("S", "U"))
        c = ImpactMetric.from_code(components.get("C", "N"))
        i = ImpactMetric.from_code(components.get("I", "N"))
        a = ImpactMetric.from_code(components.get("A", "N"))
        
        return cls(
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'attack_vector': self.attack_vector.code,
            'attack_complexity': self.attack_complexity.code,
            'privileges_required': self.privileges_required.code,
            'user_interaction': self.user_interaction.code,
            'scope': self.scope.code,
            'confidentiality': self.confidentiality.code,
            'integrity': self.integrity.code,
            'availability': self.availability.code,
            'vector': self.to_vector_string()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CVSSVector':
        """Create from dictionary."""
        return cls(
            attack_vector=AttackVector.from_code(data.get('attack_vector', 'N')),
            attack_complexity=AttackComplexity.from_code(data.get('attack_complexity', 'L')),
            privileges_required=PrivilegesRequired.from_code(data.get('privileges_required', 'N')),
            user_interaction=UserInteraction.from_code(data.get('user_interaction', 'N')),
            scope=Scope.from_code(data.get('scope', 'U')),
            confidentiality=ImpactMetric.from_code(data.get('confidentiality', 'N')),
            integrity=ImpactMetric.from_code(data.get('integrity', 'N')),
            availability=ImpactMetric.from_code(data.get('availability', 'N'))
        )


@dataclass
class CVSSScore:
    """
    CVSS v3.1 Score calculation result.
    """
    vector: CVSSVector
    base_score: float
    impact_score: float
    exploitability_score: float
    
    # Severity rating based on base score
    severity: str = ""  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vector': self.vector.to_vector_string(),
            'base_score': round(self.base_score, 1),
            'impact_score': round(self.impact_score, 1),
            'exploitability_score': round(self.exploitability_score, 1),
            'severity': self.severity
        }


class CVSSCalculator:
    """
    CVSS v3.1 Calculator.
    
    Implements the CVSS v3.1 specification for calculating base scores.
    Reference: https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf
    """
    
    # Severity thresholds
    SEVERITY_NONE = (0.0, "NONE")
    SEVERITY_LOW = (0.1, "LOW")
    SEVERITY_MEDIUM = (4.0, "MEDIUM")
    SEVERITY_HIGH = (7.0, "HIGH")
    SEVERITY_CRITICAL = (9.0, "CRITICAL")
    
    @staticmethod
    def get_severity(base_score: float) -> str:
        """Get severity rating from base score."""
        if base_score == 0:
            return "NONE"
        elif base_score < 4.0:
            return "LOW"
        elif base_score < 7.0:
            return "MEDIUM"
        elif base_score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"
    
    @staticmethod
    def calculate_impact_subscore(
        confidentiality: ImpactMetric,
        integrity: ImpactMetric,
        availability: ImpactMetric
    ) -> float:
        """
        Calculate Impact Subscore (ISS).
        
        ISS = 1 - (1 - Confidentiality) * (1 - Integrity) * (1 - Availability)
        """
        c = confidentiality.numeric_value
        i = integrity.numeric_value
        a = availability.numeric_value
        
        return 1 - (1 - c) * (1 - i) * (1 - a)
    
    @staticmethod
    def calculate_impact_score(
        iss: float,
        scope: Scope
    ) -> float:
        """
        Calculate Impact Score.
        
        If Scope is Unchanged:
            Impact = 6.42 * ISS
        If Scope is Changed:
            Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15
        """
        if scope == Scope.UNCHANGED:
            return 6.42 * iss
        else:  # Scope is CHANGED
            # Simplified approximation
            return 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    
    @staticmethod
    def calculate_exploitability_score(
        attack_vector: AttackVector,
        attack_complexity: AttackComplexity,
        privileges_required: PrivilegesRequired,
        user_interaction: UserInteraction
    ) -> float:
        """
        Calculate Exploitability Score.
        
        Exploitability = 8.22 * AV * AC * PR * UI
        """
        return 8.22 * (
            attack_vector.numeric_value *
            attack_complexity.numeric_value *
            privileges_required.numeric_value *
            user_interaction.numeric_value
        )
    
    def calculate(self, vector: CVSSVector) -> CVSSScore:
        """
        Calculate CVSS v3.1 base score from vector.
        
        Args:
            vector: CVSSVector with all metric values
            
        Returns:
            CVSSScore with base score, impact score, exploitability score, and severity
        """
        # Calculate Impact Subscore (ISS)
        iss = self.calculate_impact_subscore(
            vector.confidentiality,
            vector.integrity,
            vector.availability
        )
        
        # If ISS is 0, base score is 0
        if iss == 0:
            return CVSSScore(
                vector=vector,
                base_score=0.0,
                impact_score=0.0,
                exploitability_score=0.0,
                severity="NONE"
            )
        
        # Calculate Impact Score
        impact_score = self.calculate_impact_score(iss, vector.scope)
        
        # Calculate Exploitability Score
        exploitability_score = self.calculate_exploitability_score(
            vector.attack_vector,
            vector.attack_complexity,
            vector.privileges_required,
            vector.user_interaction
        )
        
        # Calculate Base Score
        if vector.scope == Scope.UNCHANGED:
            base_score = min(1.08 * (impact_score + exploitability_score), 10)
        else:  # Scope is CHANGED
            base_score = min(1.08 * (impact_score + exploitability_score), 10)
        
        # Round to 1 decimal place (CVSS standard)
        base_score = round(base_score, 1)
        impact_score = round(impact_score, 1)
        exploitability_score = round(exploitability_score, 1)
        
        # Determine severity
        severity = self.get_severity(base_score)
        
        return CVSSScore(
            vector=vector,
            base_score=base_score,
            impact_score=impact_score,
            exploitability_score=exploitability_score,
            severity=severity
        )
    
    def calculate_from_vector_string(self, vector_string: str) -> CVSSScore:
        """
        Calculate CVSS score from vector string.
        
        Args:
            vector_string: CVSS vector string (e.g., "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
            
        Returns:
            CVSSScore with calculated values
        """
        vector = CVSSVector.from_vector_string(vector_string)
        return self.calculate(vector)
    
    def calculate_from_metrics(
        self,
        av: str,
        ac: str,
        pr: str,
        ui: str,
        s: str,
        c: str,
        i: str,
        a: str
    ) -> CVSSScore:
        """
        Calculate CVSS score from individual metric codes.
        
        Args:
            av: Attack Vector code (N, A, L, P)
            ac: Attack Complexity code (L, H)
            pr: Privileges Required code (N, L, H)
            ui: User Interaction code (N, R)
            s: Scope code (U, C)
            c: Confidentiality code (N, L, H)
            i: Integrity code (N, L, H)
            a: Availability code (N, L, H)
            
        Returns:
            CVSSScore with calculated values
        """
        vector = CVSSVector(
            attack_vector=AttackVector.from_code(av),
            attack_complexity=AttackComplexity.from_code(ac),
            privileges_required=PrivilegesRequired.from_code(pr),
            user_interaction=UserInteraction.from_code(ui),
            scope=Scope.from_code(s),
            confidentiality=ImpactMetric.from_code(c),
            integrity=ImpactMetric.from_code(i),
            availability=ImpactMetric.from_code(a)
        )
        return self.calculate(vector)


# Pre-defined vectors for common vulnerability types
def get_cvss_for_vulnerability_type(vuln_type: str) -> Optional[CVSSVector]:
    """
    Get a pre-defined CVSS vector for common vulnerability types.
    
    Args:
        vuln_type: Vulnerability type (e.g., 'sqli', 'xss', 'idor')
        
    Returns:
        CVSSVector or None if no pre-defined vector exists
    """
    # Common vulnerability vectors
    vulnerability_vectors = {
        # SQL Injection
        'sqli': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        ),
        # Cross-Site Scripting (XSS)
        'xss': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=ImpactMetric.LOW,
            integrity=ImpactMetric.LOW,
            availability=ImpactMetric.NONE
        ),
        # IDOR (Insecure Direct Object Reference)
        'idor': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.NONE
        ),
        # BOLA (Broken Object Level Authorization)
        'bola': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.NONE
        ),
        # SSRF (Server-Side Request Forgery)
        'ssrf': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        ),
        # RCE (Remote Code Execution)
        'rce': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        ),
        # LFI (Local File Inclusion)
        'lfi': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.LOW,
            availability=ImpactMetric.NONE
        ),
        # Command Injection
        'command_injection': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        ),
        # XXE (XML External Entity)
        'xxe': CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH
        ),
    }
    
    return vulnerability_vectors.get(vuln_type.lower())


# Singleton calculator instance
_calculator = None


def get_calculator() -> CVSSCalculator:
    """Get singleton CVSSCalculator instance."""
    global _calculator
    if _calculator is None:
        _calculator = CVSSCalculator()
    return _calculator


# Convenience functions
def calculate_cvss(vector_string: str) -> CVSSScore:
    """Calculate CVSS score from vector string."""
    return get_calculator().calculate_from_vector_string(vector_string)


def calculate_cvss_from_metrics(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> CVSSScore:
    """Calculate CVSS score from individual metrics."""
    return get_calculator().calculate_from_metrics(av, ac, pr, ui, s, c, i, a)


def get_cvss_vector(vuln_type: str) -> Optional[CVSSVector]:
    """Get CVSS vector for vulnerability type."""
    return get_cvss_for_vulnerability_type(vuln_type)
