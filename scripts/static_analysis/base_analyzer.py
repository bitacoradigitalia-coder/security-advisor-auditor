"""
Base Analyzer for Security Advisor Auditor v3.0
Abstract base class for all static analysis tools.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import re


@dataclass
class Finding:
    """Represents a security finding from static analysis."""
    
    # Identification
    id: str = field(default_factory=lambda: str(id(Finding)))
    tool: str = ""
    language: str = ""
    
    # Classification
    severity: str = "medium"  # critical, high, medium, low, info
    confidence: str = "medium"  # high, medium, low
    type: str = "vulnerability"  # vulnerability, risk, hardening, informational
    category: str = ""  # sqli, xss, rce, etc.
    
    # Details
    title: str = ""
    message: str = ""
    description: str = ""
    
    # Location
    file: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    code: str = ""
    
    # Evidence
    evidence: str = ""
    proof_of_concept: str = ""
    
    # Remediation
    remediation: str = ""
    fix: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'id': self.id,
            'tool': self.tool,
            'language': self.language,
            'severity': self.severity,
            'confidence': self.confidence,
            'type': self.type,
            'category': self.category,
            'title': self.title,
            'message': self.message,
            'description': self.description,
            'file': self.file,
            'line': self.line,
            'column': self.column,
            'code': self.code,
            'evidence': self.evidence,
            'proof_of_concept': self.proof_of_concept,
            'remediation': self.remediation,
            'fix': self.fix,
            'references': self.references,
            'tags': self.tags,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary."""
        return cls(
            id=data.get('id', ''),
            tool=data.get('tool', ''),
            language=data.get('language', ''),
            severity=data.get('severity', 'medium'),
            confidence=data.get('confidence', 'medium'),
            type=data.get('type', 'vulnerability'),
            category=data.get('category', ''),
            title=data.get('title', ''),
            message=data.get('message', ''),
            description=data.get('description', ''),
            file=data.get('file', ''),
            line=data.get('line'),
            column=data.get('column'),
            code=data.get('code', ''),
            evidence=data.get('evidence', ''),
            proof_of_concept=data.get('proof_of_concept', ''),
            remediation=data.get('remediation', ''),
            fix=data.get('fix', ''),
            references=data.get('references', []),
            tags=data.get('tags', []),
            cvss_score=data.get('cvss_score'),
            cvss_vector=data.get('cvss_vector', ''),
        )


@dataclass
class ScanResult:
    """Result of a static analysis scan."""
    
    target: str
    tool: str
    language: str = ""
    findings: List[Finding] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    success: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'tool': self.tool,
            'language': self.language,
            'findings': [f.to_dict() for f in self.findings],
            'statistics': self.statistics,
            'errors': self.errors,
            'success': self.success,
        }


class BaseAnalyzer(ABC):
    """
    Abstract base class for static analysis tools.
    All analyzers should inherit from this class.
    """
    
    # Tool name (to be overridden by subclasses)
    TOOL_NAME: str = "base_analyzer"
    
    # Supported languages (to be overridden by subclasses)
    SUPPORTED_LANGUAGES: List[str] = []
    
    # Severity mapping for normalization
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'informational': 'info',
        'warning': 'medium',
        'error': 'high',
    }
    
    # Confidence mapping
    CONFIDENCE_MAP = {
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
    }
    
    def __init__(self):
        """Initialize the analyzer."""
        self._validate_installation()
    
    def _validate_installation(self) -> None:
        """Validate that the tool is installed and accessible."""
        # To be implemented by subclasses
        pass
    
    def analyze_file(self, file_path: Union[str, Path], language: str = None) -> ScanResult:
        """
        Analyze a single file.
        
        Args:
            file_path: Path to the file to analyze
            language: Language of the file (optional)
        
        Returns:
            ScanResult with findings
        """
        # Default implementation for tools that don't support file analysis
        return ScanResult(
            target=str(file_path),
            tool=self.TOOL_NAME,
            language=language or "",
            findings=[],
            errors=[f"{self.TOOL_NAME} does not support file analysis"],
            success=False
        )
    
    def analyze_code(self, code: str, language: str, file_path: str = "<stdin>") -> ScanResult:
        """
        Analyze code directly (without file).
        
        Args:
            code: Source code to analyze
            language: Language of the code
            file_path: Virtual file path (default: <stdin>)
        
        Returns:
            ScanResult with findings
        """
        # Default implementation for tools that don't support code analysis
        return ScanResult(
            target=file_path,
            tool=self.TOOL_NAME,
            language=language,
            findings=[],
            errors=[f"{self.TOOL_NAME} does not support code analysis"],
            success=False
        )
    
    def analyze_directory(self, dir_path: Union[str, Path], languages: List[str] = None) -> ScanResult:
        """
        Analyze all files in a directory.
        
        Args:
            dir_path: Path to the directory
            languages: List of languages to analyze (optional)
        
        Returns:
            ScanResult with all findings
        """
        # Default implementation for tools that don't support directory analysis
        return ScanResult(
            target=str(dir_path),
            tool=self.TOOL_NAME,
            language=",".join(languages) if languages else "",
            findings=[],
            errors=[f"{self.TOOL_NAME} does not support directory analysis"],
            success=False
        )
    
    def is_available(self) -> bool:
        """Check if the tool is available."""
        return True
    
    def get_name(self) -> str:
        """Get the tool name."""
        return self.TOOL_NAME
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages."""
        return self.SUPPORTED_LANGUAGES
    
    def normalize_finding(self, finding: Dict[str, Any], language: str = None) -> Finding:
        """
        Normalize a finding to the standard Finding format.
        
        Args:
            finding: Raw finding from the tool
            language: Language of the finding
        
        Returns:
            Normalized Finding object
        """
        return Finding(
            tool=self.TOOL_NAME,
            language=language or finding.get('language', ''),
            severity=self.SEVERITY_MAP.get(finding.get('severity', 'medium').lower(), 'medium'),
            confidence=self.CONFIDENCE_MAP.get(finding.get('confidence', 'medium').lower(), 'medium'),
            type=finding.get('type', 'vulnerability'),
            category=finding.get('category', finding.get('rule_id', '')),
            title=finding.get('title', finding.get('message', 'Untitled Finding')),
            message=finding.get('message', ''),
            description=finding.get('description', finding.get('message', '')),
            file=finding.get('file', finding.get('path', '')),
            line=finding.get('line', finding.get('start', {}).get('line')),
            column=finding.get('column', finding.get('start', {}).get('col')),
            code=finding.get('code', finding.get('lines', '')),
            evidence=finding.get('evidence', ''),
            proof_of_concept=finding.get('proof_of_concept', ''),
            remediation=finding.get('remediation', finding.get('fix', '')),
            fix=finding.get('fix', ''),
            references=finding.get('references', []),
            tags=finding.get('tags', []),
            cvss_score=finding.get('cvss_score'),
            cvss_vector=finding.get('cvss_vector', ''),
        )
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in findings:
            severity = finding.severity.lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_category(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by category."""
        counts = {}
        for finding in findings:
            category = finding.category.lower() if finding.category else 'other'
            counts[category] = counts.get(category, 0) + 1
        return counts
