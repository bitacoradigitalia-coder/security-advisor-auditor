"""
Unit tests for the native JavaScript and TypeScript analyzers (FASE 4, issue #2)
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from static_analysis import JavaScriptAnalyzer, TypeScriptAnalyzer, get_analyzer
from static_analysis.js_analyzer import JS_RULES
from static_analysis.ts_analyzer import TS_RULES
from static_analysis.regex_rules import RuleEngine

VULNERABLE_JS = """
const userId = req.params.id;
eval("calculate(" + userId + ")");
document.write("<h1>" + userId + "</h1>");
element.innerHTML = userId;
const q = "SELECT * FROM users WHERE id = " + userId;
const apiKey = "sk_live_abcdef1234567890";
const child = require('child_process');
child.exec("convert " + req.body.filename);
"""

CLEAN_JS = """
const userId = String(req.params.id || '');
const node = document.createElement('h1');
node.textContent = userId;
container.appendChild(node);
const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
stmt.run(userId);
"""

VULNERABLE_TS = """
function handle(req: Request): any {
    const data = req.body as any;
    // @ts-ignore
    const unsafe = riskyOperation(data)!;
    const forced = data as unknown as InternalType;
    return unsafe;
}
"""

CLEAN_TS = """
export function handle(req: Request): Response {
    const id = Number(req.params.id);
    return new Response(String(id));
}
"""


class TestRuleEngine(unittest.TestCase):
    """Tests para el motor de reglas compartido"""

    def test_rules_have_ids(self):
        ids = [r.rule_id for r in JS_RULES]
        self.assertEqual(len(ids), len(set(ids)), "IDs de reglas JS duplicados")
        ts_ids = [r.rule_id for r in TS_RULES]
        self.assertEqual(len(ts_ids), len(set(ts_ids)), "IDs de reglas TS duplicados")

    def test_engine_scans_code(self):
        engine = RuleEngine("test_tool", "javascript", JS_RULES)
        findings = engine.scan_code("eval(userInput);", file_path="t.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "rce")
        self.assertEqual(findings[0].line, 1)


class TestJavaScriptAnalyzer(unittest.TestCase):
    """Tests del analizador nativo JavaScript"""

    def setUp(self):
        self.analyzer = JavaScriptAnalyzer()

    def test_tool_metadata(self):
        self.assertEqual(self.analyzer.TOOL_NAME, "js_native")
        self.assertIn("javascript", self.analyzer.get_supported_languages())
        self.assertTrue(self.analyzer.is_available())

    def test_detects_vulnerable_code(self):
        result = self.analyzer.analyze_code(VULNERABLE_JS)
        self.assertTrue(result.success)
        categories = [f.category for f in result.findings]
        self.assertIn("rce", categories)          # eval
        self.assertIn("xss", categories)          # innerHTML / document.write
        self.assertIn("sqli", categories)         # concatenacion SQL
        self.assertIn("hardcoded_secret", categories)
        self.assertIn("command_injection", categories)

    def test_clean_code_no_findings(self):
        result = self.analyzer.analyze_code(CLEAN_JS)
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 0)

    def test_finding_fields(self):
        result = self.analyzer.analyze_code("eval(x);", file_path="app.js")
        finding = result.findings[0]
        self.assertEqual(finding.tool, "js_native")
        self.assertEqual(finding.language, "javascript")
        self.assertEqual(finding.file, "app.js")
        self.assertEqual(finding.line, 1)
        self.assertTrue(finding.remediation)

    def test_analyze_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write("eval(userInput);")
            path = fh.name
        try:
            result = self.analyzer.analyze_file(path)
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_analyze_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.js").write_text("eval(x);")
            (root / "b.js").write_text("const ok = 1;")
            (root / "c.ts").write_text("eval(y);")  # no debe escanear el TS
            result = self.analyzer.analyze_directory(root)
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)

    def test_missing_file_fails_gracefully(self):
        result = self.analyzer.analyze_file("/no/existe/file.js")
        self.assertFalse(result.success)
        self.assertEqual(len(result.findings), 0)

    def test_statistics(self):
        result = self.analyzer.analyze_code(VULNERABLE_JS)
        self.assertIn("by_severity", result.statistics)
        self.assertIn("by_category", result.statistics)


class TestTypeScriptAnalyzer(unittest.TestCase):
    """Tests del analizador nativo TypeScript"""

    def setUp(self):
        self.analyzer = TypeScriptAnalyzer()

    def test_tool_metadata(self):
        self.assertEqual(self.analyzer.TOOL_NAME, "ts_native")
        self.assertIn("typescript", self.analyzer.get_supported_languages())

    def test_inherits_js_rules(self):
        from static_analysis.js_analyzer import JavaScriptAnalyzer
        self.assertGreater(len(self.analyzer.engine.rules), len(JavaScriptAnalyzer().engine.rules))

    def test_detects_ts_specific(self):
        result = self.analyzer.analyze_code(VULNERABLE_TS)
        categories = [f.category for f in result.findings]
        self.assertIn("unsafe_cast", categories)      # as any / as unknown as
        self.assertIn("suppressed_error", categories)  # @ts-ignore

    def test_detects_js_rules_in_ts(self):
        result = self.analyzer.analyze_code("eval(x);")
        self.assertEqual(result.findings[0].language, "typescript")

    def test_clean_ts_no_findings(self):
        result = self.analyzer.analyze_code(CLEAN_TS)
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 0)

    def test_analyze_directory_only_ts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.ts").write_text("eval(x);")
            (root / "b.tsx").write_text("const y = 1 as any;")
            (root / "c.js").write_text("eval(z);")  # no debe escanear el JS
            result = self.analyzer.analyze_directory(root)
            self.assertEqual(len(result.findings), 2)


class TestGetAnalyzer(unittest.TestCase):
    """Tests del factory get_analyzer"""

    def test_javascript_returns_native(self):
        analyzer = get_analyzer(language="javascript")
        self.assertIsInstance(analyzer, JavaScriptAnalyzer)

    def test_typescript_returns_native(self):
        analyzer = get_analyzer(language="typescript")
        self.assertIsInstance(analyzer, TypeScriptAnalyzer)

    def test_tool_override(self):
        analyzer = get_analyzer(tool="ts_native")
        self.assertIsInstance(analyzer, TypeScriptAnalyzer)


if __name__ == "__main__":
    unittest.main()
