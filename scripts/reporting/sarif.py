"""
SARIF 2.1.0 Exporter for Security Advisor Auditor v2.3
Exports findings to SARIF (Static Analysis Results Interchange Format) v2.1.0.

SARIF is a standard JSON-based format for the output of static analysis tools.
Reference: https://sarifweb.azurewebsites.net/

This module allows Security Advisor Auditor findings to be:
- Uploaded to GitHub Code Scanning
- Imported into other analysis tools
- Stored in a standardized format
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from urllib.parse import urlparse

# Import core components
try:
    from scripts.core.evidence_engine import Finding, Evidence, EvidenceType
    from scripts.core.cvss import CVSSVector, CVSSCalculator, CVSSScore
    EVIDENCE_AVAILABLE = True
except ImportError:
    EVIDENCE_AVAILABLE = False
    Finding = None
    Evidence = None


# SARIF Schema version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


@dataclass
class SarifLocation:
    """SARIF Location object."""
    start_line: Optional[int] = None
    start_column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    physical_location: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.start_line is not None:
            result['startLine'] = self.start_line
        if self.start_column is not None:
            result['startColumn'] = self.start_column
        if self.end_line is not None:
            result['endLine'] = self.end_line
        if self.end_column is not None:
            result['endColumn'] = self.end_column
        if self.physical_location is not None:
            result['physicalLocation'] = self.physical_location
        return result


@dataclass
class SarifPhysicalLocation:
    """SARIF Physical Location object."""
    artifact_location: Dict[str, Any]
    region: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {'artifactLocation': self.artifact_location}
        if self.region is not None:
            result['region'] = self.region
        return result


@dataclass
class SarifArtifactLocation:
    """SARIF Artifact Location object."""
    uri: str
    uri_base_id: Optional[str] = None
    index: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {'uri': self.uri}
        if self.uri_base_id is not None:
            result['uriBaseId'] = self.uri_base_id
        if self.index is not None:
            result['index'] = self.index
        return result


@dataclass
class SarifMessage:
    """SARIF Message object."""
    text: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {'text': self.text}


@dataclass
class SarifMultiformatMessageString:
    """SARIF Multiformat Message String object."""
    text: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {'text': self.text}


@dataclass
class SarifResult:
    """SARIF Result object (represents a single finding)."""
    rule_id: str
    rule_index: int
    level: str  # note, warning, error
    message: SarifMessage
    locations: List[SarifLocation] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'ruleId': self.rule_id,
            'ruleIndex': self.rule_index,
            'level': self.level,
            'message': self.message.to_dict()
        }
        if self.locations:
            result['locations'] = [loc.to_dict() for loc in self.locations]
        if self.properties:
            result['properties'] = self.properties
        return result


@dataclass
class SarifToolComponent:
    """SARIF Tool Component object."""
    name: str
    version: Optional[str] = None
    information_uri: Optional[str] = None
    rules: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {'name': self.name}
        if self.version is not None:
            result['version'] = self.version
        if self.information_uri is not None:
            result['informationUri'] = self.information_uri
        if self.rules:
            result['rules'] = self.rules
        return result


@dataclass
class SarifTool:
    """SARIF Tool object."""
    driver: SarifToolComponent
    extensions: List[SarifToolComponent] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {'driver': self.driver.to_dict()}
        if self.extensions:
            result['extensions'] = [ext.to_dict() for ext in self.extensions]
        return result


@dataclass
class SarifRun:
    """SARIF Run object (represents a single scan/run)."""
    tool: SarifTool
    results: List[SarifResult] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    invocations: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'tool': self.tool.to_dict(),
            'results': [r.to_dict() for r in self.results]
        }
        if self.artifacts:
            result['artifacts'] = self.artifacts
        if self.invocations:
            result['invocations'] = self.invocations
        return result


@dataclass
class SarifLog:
    """SARIF Log object (root object)."""
    schema: str = SARIF_SCHEMA
    version: str = SARIF_VERSION
    runs: List[SarifRun] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            '$schema': self.schema,
            'version': self.version,
            'runs': [run.to_dict() for run in self.runs]
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class SarifExporter:
    """
    Exports Security Advisor Auditor findings to SARIF 2.1.0 format.
    
    This exporter:
    - Converts Finding objects to SARIF Result objects
    - Maps severity levels to SARIF levels
    - Includes CWE, CVSS, and other metadata in properties
    - Generates proper location information
    - Supports multiple runs (for different scan types)
    """
    
    # Tool information
    TOOL_NAME = "Security Advisor Auditor"
    TOOL_VERSION = "2.3.0"
    TOOL_INFO_URI = "https://github.com/bitacoradigitalia-coder/security-advisor-auditor"
    
    # Severity mapping to SARIF levels
    SEVERITY_MAP = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'warning',
        'info': 'note'
    }
    
    # Default level for unknown severities
    DEFAULT_LEVEL = 'warning'
    
    def __init__(
        self,
        tool_name: Optional[str] = None,
        tool_version: Optional[str] = None,
        tool_info_uri: Optional[str] = None
    ):
        """
        Initialize SarifExporter.
        
        Args:
            tool_name: Name of the tool (default: Security Advisor Auditor)
            tool_version: Version of the tool (default: 2.3.0)
            tool_info_uri: Information URI for the tool
        """
        self.tool_name = tool_name or self.TOOL_NAME
        self.tool_version = tool_version or self.TOOL_VERSION
        self.tool_info_uri = tool_info_uri or self.TOOL_INFO_URI
        
        # Rule cache to avoid duplicates
        self._rules_cache: Dict[str, Dict[str, Any]] = {}
        self._rule_index: Dict[str, int] = {}
        self._next_rule_index = 0
    
    def _get_sarif_level(self, severity: str) -> str:
        """Map Security Advisor Auditor severity to SARIF level."""
        return self.SEVERITY_MAP.get(severity.lower(), self.DEFAULT_LEVEL)
    
    def _parse_location(self, location: Optional[str]) -> Optional[SarifLocation]:
        """
        Parse location string to SARIF Location.
        
        Location can be:
        - "file.py:10" -> file.py, line 10
        - "file.py:10:5" -> file.py, line 10, column 5
        - "https://example.com/api#param" -> URL with fragment
        - "/api/endpoint" -> path
        """
        if not location:
            return None
        
        # Try to parse file:line[:column] format
        if ':' in location and not location.startswith(('http://', 'https://')):
            parts = location.split(':')
            file_path = parts[0]
            
            # Parse line and optional column
            if len(parts) >= 2:
                try:
                    start_line = int(parts[1])
                except ValueError:
                    start_line = None
                
                if len(parts) >= 3:
                    try:
                        start_column = int(parts[2])
                    except ValueError:
                        start_column = None
                else:
                    start_column = None
            else:
                start_line = None
                start_column = None
            
            if start_line is not None:
                artifact_location = SarifArtifactLocation(uri=file_path).to_dict()
                physical_location = SarifPhysicalLocation(
                    artifact_location=artifact_location,
                    region={'startLine': start_line, 'startColumn': start_column}
                ).to_dict()
                
                return SarifLocation(
                    start_line=start_line,
                    start_column=start_column,
                    physical_location=physical_location
                )
        
        # For URLs and other formats, just use as URI
        artifact_location = SarifArtifactLocation(uri=location).to_dict()
        physical_location = SarifPhysicalLocation(
            artifact_location=artifact_location
        ).to_dict()
        
        return SarifLocation(physical_location=physical_location)
    
    def _parse_endpoint(self, endpoint: Optional[str]) -> Optional[SarifLocation]:
        """Parse endpoint URL to SARIF Location."""
        if not endpoint:
            return None
        
        # Try to parse URL
        try:
            parsed = urlparse(endpoint)
            path = parsed.path or '/'
            query = parsed.query
            fragment = parsed.fragment
            
            # Use path as URI
            uri = f"{parsed.scheme}://{parsed.netloc}{path}"
            if query:
                uri += f"?{query}"
            
            artifact_location = SarifArtifactLocation(uri=uri).to_dict()
            
            # If there's a fragment (e.g., #param), use it as region
            region = None
            if fragment:
                region = {'startLine': 1, 'message': {'text': f"Parameter: {fragment}"}}
            
            physical_location = SarifPhysicalLocation(
                artifact_location=artifact_location,
                region=region
            ).to_dict()
            
            return SarifLocation(physical_location=physical_location)
        except Exception:
            return SarifArtifactLocation(uri=endpoint).to_dict()
    
    def _create_rule(self, finding: Any) -> Dict[str, Any]:
        """Create SARIF rule from Finding."""
        rule_id = finding.vulnerability_type or finding.name or "UNKNOWN"
        
        # Check cache
        if rule_id in self._rules_cache:
            return self._rules_cache[rule_id]
        
        # Create rule
        rule = {
            'id': rule_id,
            'name': finding.name or rule_id,
            'shortDescription': {'text': finding.description[:200] if finding.description else rule_id},
            'fullDescription': {'text': finding.description or ''},
            'helpUri': f"https://cwe.mitre.org/data/xml/cwec_v4.12.xml.zip/{finding.cwe}.html" if finding.cwe else None,
            'properties': {
                'tags': [finding.vulnerability_type] if finding.vulnerability_type else []
            }
        }
        
        # Add CWE if available
        if finding.cwe:
            rule['properties']['cwe'] = finding.cwe
        
        # Add CVSS if available
        if finding.cvss:
            rule['properties']['cvss'] = finding.cvss
        
        # Cache rule
        self._rules_cache[rule_id] = rule
        
        return rule
    
    def _get_rule_index(self, rule_id: str) -> int:
        """Get or create rule index."""
        if rule_id not in self._rule_index:
            self._rule_index[rule_id] = self._next_rule_index
            self._next_rule_index += 1
        return self._rule_index[rule_id]
    
    def _create_sarif_result(self, finding: Any) -> SarifResult:
        """Create SARIF Result from Finding."""
        # Get rule ID
        rule_id = finding.vulnerability_type or finding.name or "UNKNOWN"
        
        # Get rule index
        rule_index = self._get_rule_index(rule_id)
        
        # Get SARIF level
        level = self._get_sarif_level(finding.severity)
        
        # Create message
        message_text = finding.description or finding.name or "No description"
        message = SarifMessage(text=message_text)
        
        # Create locations
        locations = []
        
        # Add endpoint location if available
        if finding.endpoint:
            endpoint_location = self._parse_endpoint(finding.endpoint)
            if endpoint_location:
                locations.append(endpoint_location)
        
        # Add location if available
        if finding.location:
            file_location = self._parse_location(finding.location)
            if file_location:
                locations.append(file_location)
        
        # Create properties
        properties = {
            'finding_id': finding.finding_id,
            'severity': finding.severity,
            'confidence': finding.confidence.value if hasattr(finding.confidence, 'value') else str(finding.confidence),
            'verification_status': finding.verification_status.value if hasattr(finding.verification_status, 'value') else str(finding.verification_status),
            'source': finding.source,
            'tool': finding.tool
        }
        
        # Add CWE
        if finding.cwe:
            properties['cwe'] = finding.cwe
        
        # Add CVSS
        if finding.cvss:
            properties['cvss'] = finding.cvss
        
        # Add vulnerability type
        if finding.vulnerability_type:
            properties['vulnerability_type'] = finding.vulnerability_type
        
        # Add reproduction steps
        if finding.reproduction_steps:
            properties['reproduction_steps'] = finding.reproduction_steps
        
        # Add recommendation
        if finding.recommendation:
            properties['recommendation'] = finding.recommendation
        
        # Add impact
        if finding.impact:
            properties['impact'] = finding.impact
        
        # Add references
        if finding.references:
            properties['references'] = finding.references
        
        # Add timestamp
        if finding.timestamp:
            properties['timestamp'] = finding.timestamp.isoformat()
        
        return SarifResult(
            rule_id=rule_id,
            rule_index=rule_index,
            level=level,
            message=message,
            locations=locations,
            properties=properties
        )
    
    def _create_tool_component(self, rules: List[Dict[str, Any]]) -> SarifToolComponent:
        """Create SARIF Tool Component."""
        return SarifToolComponent(
            name=self.tool_name,
            version=self.tool_version,
            information_uri=self.tool_info_uri,
            rules=rules
        )
    
    def export_findings(
        self,
        findings: List[Any],
        run_id: Optional[str] = None,
        invocation_id: Optional[str] = None
    ) -> SarifLog:
        """
        Export findings to SARIF format.
        
        Args:
            findings: List of Finding objects
            run_id: Optional run ID
            invocation_id: Optional invocation ID
            
        Returns:
            SarifLog object
        """
        # Reset caches for this export
        self._rules_cache = {}
        self._rule_index = {}
        self._next_rule_index = 0
        
        # Collect all rules
        all_rules = []
        sarif_results = []
        
        for finding in findings:
            # Create rule
            rule = self._create_rule(finding)
            if rule not in all_rules:
                all_rules.append(rule)
            
            # Create SARIF result
            sarif_result = self._create_sarif_result(finding)
            sarif_results.append(sarif_result)
        
        # Create tool component
        tool_component = self._create_tool_component(all_rules)
        
        # Create tool
        tool = SarifTool(driver=tool_component)
        
        # Create run
        run = SarifRun(
            tool=tool,
            results=sarif_results
        )
        
        # Add invocation if provided
        if invocation_id:
            run.invocations = [{
                'executionSuccessful': True,
                'toolConfigurationNotifications': [],
                'toolExecutionNotifications': []
            }]
        
        # Create log
        log = SarifLog(runs=[run])
        
        return log
    
    def export_to_file(
        self,
        findings: List[Any],
        output_path: Union[str, Path],
        run_id: Optional[str] = None,
        invocation_id: Optional[str] = None
    ) -> None:
        """
        Export findings to SARIF file.
        
        Args:
            findings: List of Finding objects
            output_path: Path to output file
            run_id: Optional run ID
            invocation_id: Optional invocation ID
        """
        sarif_log = self.export_findings(findings, run_id, invocation_id)
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sarif_log.to_json())
    
    def export_to_json(
        self,
        findings: List[Any],
        run_id: Optional[str] = None,
        invocation_id: Optional[str] = None,
        indent: int = 2
    ) -> str:
        """
        Export findings to SARIF JSON string.
        
        Args:
            findings: List of Finding objects
            run_id: Optional run ID
            invocation_id: Optional invocation ID
            indent: JSON indentation
            
        Returns:
            SARIF JSON string
        """
        sarif_log = self.export_findings(findings, run_id, invocation_id)
        return sarif_log.to_json(indent=indent)


# Convenience functions
def export_findings_to_sarif(
    findings: List[Any],
    output_path: Optional[Union[str, Path]] = None,
    tool_name: Optional[str] = None,
    tool_version: Optional[str] = None
) -> Union[str, None]:
    """
    Convenience function to export findings to SARIF.
    
    Args:
        findings: List of Finding objects
        output_path: Optional path to save SARIF file
        tool_name: Optional tool name
        tool_version: Optional tool version
        
    Returns:
        SARIF JSON string if output_path is None, otherwise None
    """
    exporter = SarifExporter(tool_name=tool_name, tool_version=tool_version)
    
    if output_path:
        exporter.export_to_file(findings, output_path)
        return None
    else:
        return exporter.export_to_json(findings)


def findings_to_sarif_json(findings: List[Any]) -> str:
    """Convert findings to SARIF JSON string."""
    return export_findings_to_sarif(findings)


def findings_to_sarif_file(findings: List[Any], output_path: Union[str, Path]) -> None:
    """Save findings to SARIF file."""
    export_findings_to_sarif(findings, output_path=output_path)
