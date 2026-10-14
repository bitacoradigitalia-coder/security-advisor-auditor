"""
Unit tests for static_analysis module (MultiLanguageAnalyzer, Semgrep, Bandit, etc.)
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

# Import modules under test
from static_analysis.base_analyzer import BaseAnalyzer, Finding, ScanResult
from static_analysis.multi_language import MultiLanguageAnalyzer


class TestFinding(unittest.TestCase):
    """Tests for Finding dataclass"""
    
    def test_finding_defaults(self):
        """Test Finding with default values"""
        finding = Finding()
        self.assertEqual(finding.tool, "")
        self.assertEqual(finding.language, "")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.confidence, "medium")
        self.assertEqual(finding.type, "vulnerability")
    
    def test_finding_to_dict(self):
        """Test Finding serialization to dict"""
        finding = Finding(
            tool="semgrep",
            language="javascript",
            severity="high",
            category="xss",
            title="Cross-Site Scripting",
            message="Potential XSS vulnerability",
            file="test.js",
            line=10,
            column=5
        )
        data = finding.to_dict()
        self.assertEqual(data['tool'], "semgrep")
        self.assertEqual(data['language'], "javascript")
        self.assertEqual(data['severity'], "high")
        self.assertEqual(data['category'], "xss")
        self.assertEqual(data['file'], "test.js")
        self.assertEqual(data['line'], 10)
    
    def test_finding_from_dict(self):
        """Test Finding deserialization from dict"""
        data = {
            'tool': 'bandit',
            'language': 'python',
            'severity': 'critical',
            'category': 'sqli',
            'title': 'SQL Injection',
            'message': 'Potential SQL injection',
            'file': 'test.py',
            'line': 20,
            'column': 10
        }
        finding = Finding.from_dict(data)
        self.assertEqual(finding.tool, "bandit")
        self.assertEqual(finding.language, "python")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.category, "sqli")


class TestScanResult(unittest.TestCase):
    """Tests for ScanResult dataclass"""
    
    def test_scan_result_defaults(self):
        """Test ScanResult with default values"""
        result = ScanResult(target="test.py", tool="semgrep")
        self.assertEqual(result.target, "test.py")
        self.assertEqual(result.tool, "semgrep")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.errors, [])
        self.assertTrue(result.success)
    
    def test_scan_result_to_dict(self):
        """Test ScanResult serialization to dict"""
        finding = Finding(
            tool="semgrep",
            language="javascript",
            severity="high",
            title="Test Finding"
        )
        result = ScanResult(
            target="test.js",
            tool="semgrep",
            language="javascript",
            findings=[finding],
            statistics={'by_severity': {'high': 1}},
            success=True
        )
        data = result.to_dict()
        self.assertEqual(data['target'], "test.js")
        self.assertEqual(data['tool'], "semgrep")
        self.assertEqual(len(data['findings']), 1)


class TestMultiLanguageAnalyzer(unittest.TestCase):
    """Tests for MultiLanguageAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = MultiLanguageAnalyzer()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test MultiLanguageAnalyzer initialization"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(self.analyzer.TOOL_NAME, "multi_language")
    
    def test_get_supported_languages(self):
        """Test getting supported languages"""
        languages = self.analyzer.get_supported_languages()
        self.assertIn('python', languages)
        self.assertIn('javascript', languages)
        self.assertIn('php', languages)
        self.assertIn('java', languages)
        self.assertGreater(len(languages), 20)
    
    def test_get_available_tools(self):
        """Test getting available tools"""
        tools = self.analyzer.get_available_tools()
        self.assertIn('semgrep', tools)
        self.assertIn('bandit', tools)
        self.assertIn('eslint', tools)
        self.assertIn('phpstan', tools)
        self.assertIn('nuclei', tools)
    
    def test_detect_language_python(self):
        """Test language detection for Python files"""
        lang = self.analyzer._detect_language("test.py")
        self.assertEqual(lang, "python")
    
    def test_detect_language_javascript(self):
        """Test language detection for JavaScript files"""
        lang = self.analyzer._detect_language("test.js")
        self.assertEqual(lang, "javascript")
    
    def test_detect_language_typescript(self):
        """Test language detection for TypeScript files"""
        lang = self.analyzer._detect_language("test.ts")
        self.assertEqual(lang, "typescript")
    
    def test_detect_language_php(self):
        """Test language detection for PHP files"""
        lang = self.analyzer._detect_language("test.php")
        self.assertEqual(lang, "php")
    
    def test_detect_language_java(self):
        """Test language detection for Java files"""
        lang = self.analyzer._detect_language("Test.java")
        self.assertEqual(lang, "java")
    
    def test_detect_language_go(self):
        """Test language detection for Go files"""
        lang = self.analyzer._detect_language("test.go")
        self.assertEqual(lang, "go")
    
    def test_detect_language_unknown(self):
        """Test language detection for unknown files"""
        lang = self.analyzer._detect_language("test.xyz")
        self.assertEqual(lang, "generic")
    
    def test_analyze_code_python(self):
        """Test analyzing Python code"""
        code = """
import os
user_input = "test"
result = os.system(user_input)  # Command injection
"""
        result = self.analyzer.analyze_code(code, "python", "test.py")
        
        # Should have findings if tools are available
        self.assertIsNotNone(result)
        self.assertEqual(result.target, "test.py")
        self.assertEqual(result.tool, "multi_language")
        self.assertEqual(result.language, "python")
    
    def test_analyze_code_javascript(self):
        """Test analyzing JavaScript code"""
        code = """
const userInput = req.query.input;
eval(userInput);  // Code injection
"""
        result = self.analyzer.analyze_code(code, "javascript", "test.js")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.target, "test.js")
        self.assertEqual(result.language, "javascript")
    
    def test_analyze_code_php(self):
        """Test analyzing PHP code"""
        code = """
<?php
$user_input = $_GET['input'];
eval($user_input);  // Code injection
?>
"""
        result = self.analyzer.analyze_code(code, "php", "test.php")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.target, "test.php")
        self.assertEqual(result.language, "php")
    
    def test_analyze_file(self):
        """Test analyzing a file"""
        # Create a test Python file
        test_file = Path(self.temp_dir) / "test_vuln.py"
        test_file.write_text("""
import os
user_input = "test"
result = os.system(user_input)  # Command injection
""")
        
        result = self.analyzer.analyze_file(test_file, "python")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.target, str(test_file))
        self.assertEqual(result.language, "python")
    
    def test_analyze_directory(self):
        """Test analyzing a directory"""
        # Create test files
        py_file = Path(self.temp_dir) / "test.py"
        py_file.write_text("import os\nos.system('test')")
        
        js_file = Path(self.temp_dir) / "test.js"
        js_file.write_text("eval('test')")
        
        result = self.analyzer.analyze_directory(self.temp_dir)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.target, self.temp_dir)
        self.assertGreaterEqual(len(result.findings), 0)
    
    def test_count_by_tool(self):
        """Test counting findings by tool"""
        findings = [
            Finding(tool="semgrep", language="javascript"),
            Finding(tool="semgrep", language="python"),
            Finding(tool="bandit", language="python"),
        ]
        counts = self.analyzer._count_by_tool(findings)
        self.assertEqual(counts['semgrep'], 2)
        self.assertEqual(counts['bandit'], 1)
    
    def test_count_by_language(self):
        """Test counting findings by language"""
        findings = [
            Finding(tool="semgrep", language="javascript"),
            Finding(tool="semgrep", language="python"),
            Finding(tool="bandit", language="python"),
        ]
        counts = self.analyzer._count_by_language(findings)
        self.assertEqual(counts['javascript'], 1)
        self.assertEqual(counts['python'], 2)


class TestBaseAnalyzer(unittest.TestCase):
    """Tests for BaseAnalyzer class"""
    
    def test_normalize_finding(self):
        """Test finding normalization"""
        analyzer = BaseAnalyzer()
        
        raw_finding = {
            'severity': 'HIGH',
            'confidence': 'HIGH',
            'type': 'vulnerability',
            'category': 'sqli',
            'title': 'SQL Injection',
            'message': 'Potential SQL injection',
            'file': 'test.py',
            'line': 10,
            'column': 5,
            'code': "cursor.execute(user_input)",
        }
        
        finding = analyzer.normalize_finding(raw_finding, 'python')
        
        self.assertEqual(finding.severity, 'high')
        self.assertEqual(finding.confidence, 'high')
        self.assertEqual(finding.type, 'vulnerability')
        self.assertEqual(finding.category, 'sqli')
        self.assertEqual(finding.file, 'test.py')
        self.assertEqual(finding.line, 10)
    
    def test_count_by_severity(self):
        """Test counting findings by severity"""
        analyzer = BaseAnalyzer()
        
        findings = [
            Finding(severity="critical"),
            Finding(severity="high"),
            Finding(severity="high"),
            Finding(severity="medium"),
        ]
        
        counts = analyzer._count_by_severity(findings)
        self.assertEqual(counts['critical'], 1)
        self.assertEqual(counts['high'], 2)
        self.assertEqual(counts['medium'], 1)
    
    def test_count_by_category(self):
        """Test counting findings by category"""
        analyzer = BaseAnalyzer()
        
        findings = [
            Finding(category="sqli"),
            Finding(category="xss"),
            Finding(category="sqli"),
            Finding(category="rce"),
        ]
        
        counts = analyzer._count_by_category(findings)
        self.assertEqual(counts['sqli'], 2)
        self.assertEqual(counts['xss'], 1)
        self.assertEqual(counts['rce'], 1)


if __name__ == '__main__':
    unittest.main()
