"""
Finding Prioritizer for Security Advisor Auditor v3.0
Prioritizes Bug Bounty findings based on multiple factors.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


@dataclass
class PriorityScore:
    """Represents a priority score for a finding."""
    finding_id: str
    score: float
    severity_score: float
    impact_score: float
    exploitability_score: float
    scope_score: float
    confidence_score: float
    
    # Individual components
    severity: str
    impact: str
    exploitability: str
    scope: str
    confidence: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'score': self.score,
            'severity_score': self.severity_score,
            'impact_score': self.impact_score,
            'exploitability_score': self.exploitability_score,
            'scope_score': self.scope_score,
            'confidence_score': self.confidence_score,
            'severity': self.severity,
            'impact': self.impact,
            'exploitability': self.exploitability,
            'scope': self.scope,
            'confidence': self.confidence
        }


class FindingPrioritizer:
    """
    Prioritizes findings based on multiple factors:
    - Severity
    - Impact
    - Exploitability
    - Scope (production, staging, development)
    - Confidence
    - Potential reward
    """
    
    # Weights for different factors (sum to 1.0)
    DEFAULT_WEIGHTS = {
        'severity': 0.35,
        'impact': 0.25,
        'exploitability': 0.20,
        'scope': 0.10,
        'confidence': 0.10
    }
    
    # Severity scores (0-10)
    SEVERITY_SCORES = {
        'critical': 10.0,
        'high': 7.0,
        'medium': 5.0,
        'low': 2.5,
        'info': 0.5
    }
    
    # Impact scores (0-10)
    IMPACT_SCORES = {
        'data_breach': 10.0,
        'rce': 9.5,
        'privilege_escalation': 9.0,
        'auth_bypass': 8.5,
        'data_manipulation': 8.0,
        'dos': 7.5,
        'xss': 7.0,
        'information_disclosure': 6.5,
        'csrf': 6.0,
        'sqli': 8.5,
        'ssrf': 7.5,
        'lfi': 7.0,
        'rfi': 7.5,
        'idor': 7.0,
        'xxe': 7.0,
        'command_injection': 9.0,
        'path_traversal': 6.5,
        'open_redirect': 5.0,
        'misconfiguration': 5.0,
        'default_credentials': 6.0
    }
    
    # Exploitability scores (0-10)
    EXPLOITABILITY_SCORES = {
        'easy': 10.0,
        'medium': 7.0,
        'hard': 4.0,
        'theoretical': 1.0
    }
    
    # Scope scores (0-10)
    SCOPE_SCORES = {
        'production': 10.0,
        'staging': 7.0,
        'development': 3.0,
        'test': 1.0,
        'unknown': 5.0
    }
    
    # Confidence scores (0-10)
    CONFIDENCE_SCORES = {
        'confirmed': 10.0,
        'high': 8.0,
        'medium': 5.0,
        'low': 2.0
    }
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize FindingPrioritizer.
        
        Args:
            weights: Custom weights for factors (optional)
        """
        self.weights = weights or self.DEFAULT_WEIGHTS
        
        # Normalize weights to sum to 1.0
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}
    
    def prioritize(self, findings: List[Dict[str, Any]]) -> List[PriorityScore]:
        """
        Prioritize a list of findings.
        
        Args:
            findings: List of finding dictionaries
        
        Returns:
            List of PriorityScore objects sorted by score (highest first)
        """
        scores = []
        
        for finding in findings:
            score = self.calculate_score(finding)
            scores.append(score)
        
        # Sort by score (descending)
        return sorted(scores, key=lambda x: x.score, reverse=True)
    
    def calculate_score(self, finding: Dict[str, Any]) -> PriorityScore:
        """
        Calculate priority score for a single finding.
        
        Args:
            finding: Finding dictionary
        
        Returns:
            PriorityScore object
        """
        # Extract values from finding
        severity = finding.get('severity', 'medium').lower()
        impact = self._get_impact(finding)
        exploitability = finding.get('exploitability', 'medium').lower()
        scope = finding.get('scope', finding.get('environment', 'unknown')).lower()
        confidence = finding.get('confidence', 'medium').lower()
        
        # Get individual scores
        severity_score = self.SEVERITY_SCORES.get(severity, 5.0)
        impact_score = self.IMPACT_SCORES.get(impact, 5.0)
        exploitability_score = self.EXPLOITABILITY_SCORES.get(exploitability, 5.0)
        scope_score = self.SCOPE_SCORES.get(scope, 5.0)
        confidence_score = self.CONFIDENCE_SCORES.get(confidence, 5.0)
        
        # Calculate weighted score
        score = (
            severity_score * self.weights.get('severity', 0.35) +
            impact_score * self.weights.get('impact', 0.25) +
            exploitability_score * self.weights.get('exploitability', 0.20) +
            scope_score * self.weights.get('scope', 0.10) +
            confidence_score * self.weights.get('confidence', 0.10)
        )
        
        return PriorityScore(
            finding_id=finding.get('id', ''),
            score=round(score, 2),
            severity_score=round(severity_score, 2),
            impact_score=round(impact_score, 2),
            exploitability_score=round(exploitability_score, 2),
            scope_score=round(scope_score, 2),
            confidence_score=round(confidence_score, 2),
            severity=severity,
            impact=impact,
            exploitability=exploitability,
            scope=scope,
            confidence=confidence
        )
    
    def _get_impact(self, finding: Dict[str, Any]) -> str:
        """
        Extract impact from finding.
        
        Args:
            finding: Finding dictionary
        
        Returns:
            Impact string
        """
        # Try to get from vulnerability type
        vuln_type = finding.get('vulnerability_type', finding.get('type', '')).lower()
        
        # Map vulnerability types to impact
        type_to_impact = {
            'sqli': 'data_breach',
            'xss': 'xss',
            'ssrf': 'information_disclosure',
            'rce': 'rce',
            'lfi': 'information_disclosure',
            'rfi': 'rce',
            'idor': 'data_manipulation',
            'xxe': 'information_disclosure',
            'csrf': 'auth_bypass',
            'command_injection': 'rce',
            'path_traversal': 'information_disclosure',
            'open_redirect': 'open_redirect'
        }
        
        if vuln_type in type_to_impact:
            return type_to_impact[vuln_type]
        
        # Try to get from impact field
        impact = finding.get('impact', '').lower()
        if impact:
            return impact
        
        # Default based on severity
        severity = finding.get('severity', 'medium').lower()
        if severity in ['critical', 'high']:
            return 'data_breach'
        elif severity == 'medium':
            return 'information_disclosure'
        else:
            return 'misconfiguration'
    
    def get_priority_level(self, score: float) -> str:
        """
        Get priority level based on score.
        
        Args:
            score: Priority score (0-10)
        
        Returns:
            Priority level string
        """
        if score >= 8.5:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 5.0:
            return 'medium'
        elif score >= 3.0:
            return 'low'
        else:
            return 'info'
    
    def get_recommendation(self, score: PriorityScore) -> str:
        """
        Get a recommendation based on the priority score.
        
        Args:
            score: PriorityScore object
        
        Returns:
            Recommendation string
        """
        priority = self.get_priority_level(score.score)
        
        recommendations = {
            'critical': "Submit immediately! This is a critical vulnerability that should be reported as soon as possible.",
            'high': "High priority. Submit within 24 hours to maximize impact.",
            'medium': "Medium priority. Submit within a few days.",
            'low': "Low priority. Consider submitting if you have time.",
            'info': "Informational. May not be worth submitting unless it's part of a larger report."
        }
        
        return recommendations.get(priority, "Review manually")
    
    def get_estimated_reward(self, score: PriorityScore, program: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Estimate potential reward based on score and program.
        
        Args:
            score: PriorityScore object
            program: Program information (optional)
        
        Returns:
            Dictionary with estimated reward range
        """
        # Base estimates based on severity
        severity_estimates = {
            'critical': {'min': 1000, 'max': 10000, 'avg': 3000},
            'high': {'min': 500, 'max': 5000, 'avg': 1500},
            'medium': {'min': 100, 'max': 2000, 'avg': 500},
            'low': {'min': 50, 'max': 500, 'avg': 100},
            'info': {'min': 0, 'max': 100, 'avg': 25}
        }
        
        severity = score.severity
        if severity not in severity_estimates:
            severity = 'medium'
        
        estimate = severity_estimates[severity].copy()
        
        # Adjust based on program if available
        if program:
            reward_range = program.get('reward_range', {})
            if reward_range:
                min_reward = reward_range.get('min', estimate['min'])
                max_reward = reward_range.get('max', estimate['max'])
                
                # Adjust our estimate
                estimate['min'] = max(estimate['min'], min_reward)
                estimate['max'] = max(estimate['max'], max_reward)
                estimate['avg'] = (estimate['min'] + estimate['max']) // 2
        
        # Adjust based on score (higher score = higher reward)
        score_factor = score.score / 10.0
        estimate['avg'] = int(estimate['avg'] * score_factor)
        
        return {
            'estimated_min': estimate['min'],
            'estimated_max': estimate['max'],
            'estimated_avg': estimate['avg'],
            'currency': 'USD',
            'confidence': 'low' if program else 'very_low'
        }
    
    def get_triage_order(self, findings: List[Dict[str, Any]]) -> List[str]:
        """
        Get the order in which findings should be triaged.
        
        Args:
            findings: List of finding dictionaries
        
        Returns:
            List of finding IDs in triage order
        """
        scores = self.prioritize(findings)
        return [s.finding_id for s in scores]
    
    def get_submission_order(self, findings: List[Dict[str, Any]]) -> List[str]:
        """
        Get the order in which findings should be submitted.
        
        Args:
            findings: List of finding dictionaries
        
        Returns:
            List of finding IDs in submission order
        """
        # Same as triage order for now
        return self.get_triage_order(findings)


# Global instance
_prioritizer: Optional[FindingPrioritizer] = None


def get_prioritizer(weights: Optional[Dict[str, float]] = None) -> FindingPrioritizer:
    """
    Get or create the global FindingPrioritizer instance.
    
    Args:
        weights: Custom weights for factors (optional)
    
    Returns:
        FindingPrioritizer instance
    """
    global _prioritizer
    if _prioritizer is None:
        _prioritizer = FindingPrioritizer(weights)
    return _prioritizer


def reset_prioritizer() -> None:
    """Reset the global FindingPrioritizer instance."""
    global _prioritizer
    _prioritizer = None
