"""
Unit tests for SARIF 2.1.0 exporter (M16 - SARIF + CVSS)
"""
import json
import os
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

# Simple Finding class for testing
class FindingMock:
    def __init__(self, **kwargs):
        # Set default values for all required attributes
        self.finding_id = kwargs.get('finding_id', 'FINDING-001')
        self.name = kwargs.get('name', 'Test Finding')
        self.description = kwargs.get('description', 'Test description')
        self.severity = kwargs.get('severity', 'medium')
        self.vulnerability_type = kwargs.get('vulnerability_type', 'unknown')
        self.cwe = kwargs.get('cwe', None)
        self.cvss = kwargs.get('cvss', None)
        self.endpoint = kwargs.get('endpoint', None)
        self.location = kwargs.get('location', None)
        self.source = kwargs.get('source', 'test_source')
        self.tool = kwargs.get('tool', 'test_tool')
        self.confidence = kwargs.get('confidence', 'HIGH')
        self.verification_status = kwargs.get('verification_status', 'CONFIRMED')
        self.reproduction_steps = kwargs.get('reproduction_steps', [])
        self.recommendation = kwargs.get('recommendation', 'Fix the issue')
        self.impact = kwargs.get('impact', 'Medium impact')
        self.references = kwargs.get('references', [])
        self.timestamp = kwargs.get('timestamp', None)

from scripts.reporting.sarif import (
    SarifExporter, SarifLog, SarifRun, SarifTool, SarifToolComponent,
    SarifResult, SarifMessage, SarifLocation, SarifPhysicalLocation,
    SarifArtifactLocation, SarifMultiformatMessageString,
    export_findings_to_sarif, findings_to_sarif_json, findings_to_sarif_file,
    SARIF_VERSION, SARIF_SCHEMA
)

# Try to import core components
try:
    from scripts.core.evidence_engine import Finding, Evidence, ConfidenceLevel, VerificationStatus
    EVIDENCE_AVAILABLE = True
except ImportError:
    EVIDENCE_AVAILABLE = False


class TestSarifLocation(unittest.TestCase):
    """Tests for SARIF Location classes"""
    
    def test_sarif_location_defaults(self):
        """Test SarifLocation with default values"""
        location = SarifLocation()
        self.assertIsNone(location.start_line)
        self.assertIsNone(location.start_column)
        self.assertIsNone(location.physical_location)
        self.assertEqual(location.to_dict(), {})
    
    def test_sarif_location_with_values(self):
        """Test SarifLocation with values"""
        location = SarifLocation(
            start_line=10,
            start_column=5,
            end_line=15,
            end_column=10
        )
        data = location.to_dict()
        self.assertEqual(data['startLine'], 10)
        self.assertEqual(data['startColumn'], 5)
        self.assertEqual(data['endLine'], 15)
        self.assertEqual(data['endColumn'], 10)


class TestSarifArtifactLocation(unittest.TestCase):
    """Tests for SarifArtifactLocation"""
    
    def test_artifact_location_basic(self):
        """Test basic artifact location"""
        loc = SarifArtifactLocation(uri="file.py")
        data = loc.to_dict()
        self.assertEqual(data['uri'], "file.py")
    
    def test_artifact_location_with_base(self):
        """Test artifact location with base ID"""
        loc = SarifArtifactLocation(
            uri="file.py",
            uri_base_id="%SRCROOT%",
            index=0
        )
        data = loc.to_dict()
        self.assertEqual(data['uri'], "file.py")
        self.assertEqual(data['uriBaseId'], "%SRCROOT%")
        self.assertEqual(data['index'], 0)


class TestSarifPhysicalLocation(unittest.TestCase):
    """Tests for SarifPhysicalLocation"""
    
    def test_physical_location_basic(self):
        """Test basic physical location"""
        artifact_loc = SarifArtifactLocation(uri="file.py").to_dict()
        phys_loc = SarifPhysicalLocation(artifact_location=artifact_loc)
        data = phys_loc.to_dict()
        self.assertIn('artifactLocation', data)
        self.assertEqual(data['artifactLocation']['uri'], "file.py")
    
    def test_physical_location_with_region(self):
        """Test physical location with region"""
        artifact_loc = SarifArtifactLocation(uri="file.py").to_dict()
        region = {'startLine': 10, 'startColumn': 5}
        phys_loc = SarifPhysicalLocation(
            artifact_location=artifact_loc,
            region=region
        )
        data = phys_loc.to_dict()
        self.assertIn('region', data)
        self.assertEqual(data['region']['startLine'], 10)


class TestSarifMessage(unittest.TestCase):
    """Tests for SarifMessage"""
    
    def test_message_basic(self):
        """Test basic message"""
        msg = SarifMessage(text="Test message")
        data = msg.to_dict()
        self.assertEqual(data['text'], "Test message")


class TestSarifResult(unittest.TestCase):
    """Tests for SarifResult"""
    
    def test_result_basic(self):
        """Test basic result"""
        msg = SarifMessage(text="Test message")
        result = SarifResult(
            rule_id="TEST-001",
            rule_index=0,
            level="error",
            message=msg
        )
        data = result.to_dict()
        self.assertEqual(data['ruleId'], "TEST-001")
        self.assertEqual(data['ruleIndex'], 0)
        self.assertEqual(data['level'], "error")
        self.assertIn('message', data)
    
    def test_result_with_locations(self):
        """Test result with locations"""
        msg = SarifMessage(text="Test message")
        location = SarifLocation(
            start_line=10,
            physical_location=SarifPhysicalLocation(
                artifact_location=SarifArtifactLocation(uri="file.py").to_dict()
            ).to_dict()
        )
        result = SarifResult(
            rule_id="TEST-001",
            rule_index=0,
            level="error",
            message=msg,
            locations=[location]
        )
        data = result.to_dict()
        self.assertIn('locations', data)
        self.assertEqual(len(data['locations']), 1)
    
    def test_result_with_properties(self):
        """Test result with properties"""
        msg = SarifMessage(text="Test message")
        result = SarifResult(
            rule_id="TEST-001",
            rule_index=0,
            level="error",
            message=msg,
            properties={'cwe': 89, 'cvss': 9.8}
        )
        data = result.to_dict()
        self.assertIn('properties', data)
        self.assertEqual(data['properties']['cwe'], 89)


class TestSarifToolComponent(unittest.TestCase):
    """Tests for SarifToolComponent"""
    
    def test_tool_component_basic(self):
        """Test basic tool component"""
        component = SarifToolComponent(name="TestTool", version="1.0.0")
        data = component.to_dict()
        self.assertEqual(data['name'], "TestTool")
        self.assertEqual(data['version'], "1.0.0")
    
    def test_tool_component_with_rules(self):
        """Test tool component with rules"""
        rules = [{'id': 'RULE-001', 'name': 'Test Rule'}]
        component = SarifToolComponent(
            name="TestTool",
            version="1.0.0",
            rules=rules
        )
        data = component.to_dict()
        self.assertIn('rules', data)
        self.assertEqual(len(data['rules']), 1)


class TestSarifTool(unittest.TestCase):
    """Tests for SarifTool"""
    
    def test_tool_basic(self):
        """Test basic tool"""
        driver = SarifToolComponent(name="TestTool", version="1.0.0")
        tool = SarifTool(driver=driver)
        data = tool.to_dict()
        self.assertIn('driver', data)
        self.assertEqual(data['driver']['name'], "TestTool")
    
    def test_tool_with_extensions(self):
        """Test tool with extensions"""
        driver = SarifToolComponent(name="TestTool", version="1.0.0")
        extension = SarifToolComponent(name="Extension", version="1.0.0")
        tool = SarifTool(driver=driver, extensions=[extension])
        data = tool.to_dict()
        self.assertIn('extensions', data)
        self.assertEqual(len(data['extensions']), 1)


class TestSarifRun(unittest.TestCase):
    """Tests for SarifRun"""
    
    def test_run_basic(self):
        """Test basic run"""
        driver = SarifToolComponent(name="TestTool", version="1.0.0")
        tool = SarifTool(driver=driver)
        run = SarifRun(tool=tool)
        data = run.to_dict()
        self.assertIn('tool', data)
        self.assertIn('results', data)
        self.assertEqual(data['results'], [])
    
    def test_run_with_results(self):
        """Test run with results"""
        driver = SarifToolComponent(name="TestTool", version="1.0.0")
        tool = SarifTool(driver=driver)
        msg = SarifMessage(text="Test message")
        result = SarifResult(
            rule_id="TEST-001",
            rule_index=0,
            level="error",
            message=msg
        )
        run = SarifRun(tool=tool, results=[result])
        data = run.to_dict()
        self.assertEqual(len(data['results']), 1)


class TestSarifLog(unittest.TestCase):
    """Tests for SarifLog"""
    
    def test_log_basic(self):
        """Test basic log"""
        log = SarifLog()
        data = log.to_dict()
        self.assertEqual(data['version'], SARIF_VERSION)
        self.assertEqual(data['$schema'], SARIF_SCHEMA)
        self.assertIn('runs', data)
    
    def test_log_with_run(self):
        """Test log with run"""
        driver = SarifToolComponent(name="TestTool", version="1.0.0")
        tool = SarifTool(driver=driver)
        run = SarifRun(tool=tool)
        log = SarifLog(runs=[run])
        data = log.to_dict()
        self.assertEqual(len(data['runs']), 1)
    
    def test_log_to_json(self):
        """Test log to JSON conversion"""
        log = SarifLog()
        json_str = log.to_json()
        self.assertIsInstance(json_str, str)
        
        # Verify it's valid JSON
        parsed = json.loads(json_str)
        self.assertEqual(parsed['version'], SARIF_VERSION)


class TestSarifExporter(unittest.TestCase):
    """Tests for SarifExporter"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.exporter = SarifExporter(
            tool_name="TestTool",
            tool_version="1.0.0",
            tool_info_uri="https://example.com/test"
        )
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_export_findings_basic(self):
        """Test exporting basic findings"""
        # Create mock findings
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "This is a test finding"
        finding.severity = "high"
        finding.confidence = ConfidenceLevel.HIGH
        finding.verification_status = VerificationStatus.CONFIRMED
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "test.py:10"
        finding.source = "test_source"
        finding.tool = "test_tool"
        finding.reproduction_steps = ["Step 1", "Step 2"]
        finding.recommendation = "Fix the issue"
        finding.impact = "High impact"
        finding.references = ["https://example.com"]
        finding.timestamp = None
        
        findings = [finding]
        
        # Export to SARIF
        sarif_log = self.exporter.export_findings(findings)
        
        # Verify structure
        self.assertIsInstance(sarif_log, SarifLog)
        self.assertEqual(len(sarif_log.runs), 1)
        self.assertEqual(len(sarif_log.runs[0].results), 1)
        
        # Verify result
        result = sarif_log.runs[0].results[0]
        self.assertEqual(result.rule_id, "sqli")
        self.assertEqual(result.level, "error")  # high severity -> error
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_export_findings_multiple(self):
        """Test exporting multiple findings"""
        finding1 = FindingMock()
        finding1.finding_id = "FINDING-001"
        finding1.name = "Test Finding 1"
        finding1.description = "First finding"
        finding1.severity = "critical"
        finding1.vulnerability_type = "rce"
        finding1.cwe = 78
        finding1.cvss = 9.8
        finding1.endpoint = "https://example.com/api/test1"
        finding1.location = "https://example.com/api/test1"
        finding1.source = "test_source"
        finding1.tool = "test_tool"
        
        finding2 = FindingMock()
        finding2.finding_id = "FINDING-002"
        finding2.name = "Test Finding 2"
        finding2.description = "Second finding"
        finding2.severity = "medium"
        finding2.vulnerability_type = "xss"
        finding2.cwe = 79
        finding2.cvss = 6.1
        finding2.endpoint = "https://example.com/api/test2"
        finding2.location = "https://example.com/api/test2"
        finding2.source = "test_source"
        finding2.tool = "test_tool"
        
        findings = [finding1, finding2]
        
        sarif_log = self.exporter.export_findings(findings)
        
        self.assertEqual(len(sarif_log.runs[0].results), 2)
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_export_to_file(self):
        """Test exporting to file"""
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "This is a test finding"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        findings = [finding]
        
        output_path = os.path.join(self.temp_dir, "test.sarif.json")
        self.exporter.export_to_file(findings, output_path)
        
        # Verify file was created
        self.assertTrue(os.path.exists(output_path))
        
        # Verify file content
        with open(output_path, 'r') as f:
            content = f.read()
            sarif_data = json.loads(content)
        
        self.assertEqual(sarif_data['version'], SARIF_VERSION)
        self.assertEqual(sarif_data['$schema'], SARIF_SCHEMA)
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_export_to_json(self):
        """Test exporting to JSON string"""
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "This is a test finding"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        findings = [finding]
        
        json_str = self.exporter.export_to_json(findings)
        
        self.assertIsInstance(json_str, str)
        sarif_data = json.loads(json_str)
        self.assertEqual(sarif_data['version'], SARIF_VERSION)
    
    def test_severity_mapping(self):
        """Test severity to SARIF level mapping"""
        test_cases = [
            ('critical', 'error'),
            ('high', 'error'),
            ('medium', 'warning'),
            ('low', 'warning'),
            ('info', 'note'),
            ('unknown', 'warning')  # Default
        ]
        
        for severity, expected_level in test_cases:
            self.assertEqual(self.exporter._get_sarif_level(severity), expected_level)
    
    def test_parse_location_file(self):
        """Test parsing file:line location"""
        location = self.exporter._parse_location("test.py:10")
        self.assertIsNotNone(location)
        self.assertEqual(location.start_line, 10)
        self.assertIsNone(location.start_column)
    
    def test_parse_location_file_with_column(self):
        """Test parsing file:line:column location"""
        location = self.exporter._parse_location("test.py:10:5")
        self.assertIsNotNone(location)
        self.assertEqual(location.start_line, 10)
        self.assertEqual(location.start_column, 5)
    
    def test_parse_location_url(self):
        """Test parsing URL location"""
        location = self.exporter._parse_location("https://example.com/api/test")
        self.assertIsNotNone(location)
        self.assertIsNotNone(location.physical_location)
    
    def test_parse_endpoint(self):
        """Test parsing endpoint URL"""
        location = self.exporter._parse_endpoint("https://example.com/api/test")
        self.assertIsNotNone(location)
        self.assertIsNotNone(location.physical_location)
    
    def test_parse_endpoint_with_param(self):
        """Test parsing endpoint with parameter fragment"""
        location = self.exporter._parse_endpoint("https://example.com/api/test#id")
        self.assertIsNotNone(location)
        self.assertIsNotNone(location.physical_location)
        # Check that region is set for parameter
        self.assertIsNotNone(location.physical_location.get('region'))


class TestSarifConvenienceFunctions(unittest.TestCase):
    """Tests for convenience functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_export_findings_to_sarif_json(self):
        """Test export_findings_to_sarif with JSON output"""
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "Test description"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        json_str = export_findings_to_sarif([finding])
        
        self.assertIsInstance(json_str, str)
        sarif_data = json.loads(json_str)
        self.assertEqual(sarif_data['version'], SARIF_VERSION)
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_export_findings_to_sarif_file(self):
        """Test export_findings_to_sarif with file output"""
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "Test description"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        output_path = os.path.join(self.temp_dir, "test.sarif.json")
        export_findings_to_sarif([finding], output_path=output_path)
        
        self.assertTrue(os.path.exists(output_path))
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_findings_to_sarif_json(self):
        """Test findings_to_sarif_json function"""
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "Test description"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        json_str = findings_to_sarif_json([finding])
        
        self.assertIsInstance(json_str, str)
        sarif_data = json.loads(json_str)
        self.assertEqual(sarif_data['version'], SARIF_VERSION)
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_findings_to_sarif_file(self):
        """Test findings_to_sarif_file function"""
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "Test description"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        output_path = os.path.join(self.temp_dir, "test2.sarif.json")
        findings_to_sarif_file([finding], output_path)
        
        self.assertTrue(os.path.exists(output_path))


class TestSarifValidation(unittest.TestCase):
    """Tests for SARIF validation (structure and schema)"""
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_sarif_structure_valid(self):
        """Test that generated SARIF has valid structure"""
        exporter = SarifExporter()
        
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "Test description"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        sarif_log = exporter.export_findings([finding])
        sarif_dict = sarif_log.to_dict()
        
        # Check required fields
        self.assertIn('$schema', sarif_dict)
        self.assertIn('version', sarif_dict)
        self.assertIn('runs', sarif_dict)
        
        # Check run structure
        self.assertEqual(len(sarif_dict['runs']), 1)
        run = sarif_dict['runs'][0]
        self.assertIn('tool', run)
        self.assertIn('results', run)
        
        # Check tool structure
        tool = run['tool']
        self.assertIn('driver', tool)
        driver = tool['driver']
        self.assertIn('name', driver)
        self.assertIn('version', driver)
        
        # Check result structure
        self.assertEqual(len(run['results']), 1)
        result = run['results'][0]
        self.assertIn('ruleId', result)
        self.assertIn('ruleIndex', result)
        self.assertIn('level', result)
        self.assertIn('message', result)
        
        # Check message structure
        message = result['message']
        self.assertIn('text', message)
    
    @unittest.skipUnless(EVIDENCE_AVAILABLE, "Evidence engine not available")
    def test_sarif_json_valid(self):
        """Test that generated SARIF is valid JSON"""
        exporter = SarifExporter()
        
        finding = FindingMock()
        finding.finding_id = "FINDING-001"
        finding.name = "Test Finding"
        finding.description = "Test description"
        finding.severity = "high"
        finding.vulnerability_type = "sqli"
        finding.cwe = 89
        finding.cvss = 9.8
        finding.endpoint = "https://example.com/api/test"
        finding.location = "https://example.com/api/test"
        finding.source = "test_source"
        finding.tool = "test_tool"
        
        json_str = exporter.export_to_json([finding])
        
        # Should not raise exception
        sarif_data = json.loads(json_str)
        self.assertIsInstance(sarif_data, dict)


if __name__ == '__main__':
    unittest.main()
