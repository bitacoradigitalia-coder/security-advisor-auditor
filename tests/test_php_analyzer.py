"""
Unit tests del analizador nativo PHP (mejora 5 del plan v2.2)
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from static_analysis import PHPAnalyzer, get_analyzer
from static_analysis.php_analyzer import PHP_RULES

VULNERABLE_PHP = """
<?php
eval($_GET['cmd']);
system("ping " . $_GET['host']);
echo $_GET['name'];
include($_GET['page']);
mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);
unserialize($_POST['data']);
header('Location: ' . $_GET['url']);
?>
"""

CLEAN_PHP = """
<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
?>
"""


class TestPHPAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PHPAnalyzer()

    def test_tool_metadata(self):
        self.assertEqual(self.analyzer.TOOL_NAME, "php_native")
        self.assertIn("php", self.analyzer.get_supported_languages())
        self.assertTrue(self.analyzer.is_available())

    def test_rules_defined(self):
        ids = [r.rule_id for r in PHP_RULES]
        self.assertEqual(len(ids), 8)
        self.assertEqual(len(ids), len(set(ids)))

    def test_detects_vulnerable_code(self):
        result = self.analyzer.analyze_code(VULNERABLE_PHP)
        self.assertTrue(result.success)
        categories = [f.category for f in result.findings]
        self.assertIn("rce", categories)
        self.assertIn("command_injection", categories)
        self.assertIn("xss", categories)
        self.assertIn("file_inclusion", categories)
        self.assertIn("sqli", categories)
        self.assertIn("deserialization", categories)
        self.assertIn("open_redirect", categories)

    def test_clean_code_no_findings(self):
        result = self.analyzer.analyze_code(CLEAN_PHP)
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 0)

    def test_analyze_directory_only_php(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.php").write_text("<?php eval($_GET['x']); ?>")
            (root / "b.js").write_text("eval(x);")
            result = self.analyzer.analyze_directory(root)
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].language, "php")

    def test_get_analyzer(self):
        self.assertIsInstance(get_analyzer(language="php"), PHPAnalyzer)
        self.assertIsInstance(get_analyzer(tool="php_native"), PHPAnalyzer)


if __name__ == "__main__":
    unittest.main()
