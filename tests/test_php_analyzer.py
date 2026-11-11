"""Pruebas del analizador PHP con fragmentos que solo se analizan como texto."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from static_analysis import PHPAnalyzer, get_analyzer
from static_analysis.php_analyzer import PHP_RULES


class TestPHPAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PHPAnalyzer()

    def test_tool_metadata(self):
        self.assertEqual(self.analyzer.TOOL_NAME, "php_native")
        self.assertIn("php", self.analyzer.get_supported_languages())
        self.assertTrue(self.analyzer.is_available())

    def test_rules_defined(self):
        ids = [rule.rule_id for rule in PHP_RULES]
        self.assertEqual(len(ids), 8)
        self.assertEqual(len(ids), len(set(ids)))

    def test_detects_vulnerable_code(self):
        cases = {
            "rce": "eval('1 + 1');",
            "command_injection": "system('echo sample');",
            "xss": "echo $_GET['name'];",
            "file_inclusion": "include($_GET['page']);",
            "sqli": "mysql_query('SELECT 1');",
            "hardcoded_secret": "$password = 'test-placeholder';",
            "deserialization": "unserialize($_POST['data']);",
            "open_redirect": "header('Location: ' . $_GET['url']);",
        }
        for category, snippet in cases.items():
            with self.subTest(category=category):
                result = self.analyzer.analyze_code(snippet)
                self.assertTrue(result.success)
                self.assertIn(category, [finding.category for finding in result.findings])

    def test_clean_code_no_findings(self):
        result = self.analyzer.analyze_code(
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
            "$stmt->execute(['id' => $_GET['id']]);\n"
            "echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');\n"
        )
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 0)

    def test_analyze_directory_only_php(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.php").write_text("<?php eval('1 + 1');", encoding="utf-8")
            (root / "b.js").write_text("eval(x);", encoding="utf-8")
            result = self.analyzer.analyze_directory(root)
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].language, "php")

    def test_get_analyzer(self):
        self.assertIsInstance(get_analyzer(language="php"), PHPAnalyzer)
        self.assertIsInstance(get_analyzer(tool="php_native"), PHPAnalyzer)


if __name__ == "__main__":
    unittest.main()
