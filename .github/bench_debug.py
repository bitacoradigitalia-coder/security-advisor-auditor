"""Diagnostico del benchmark: muestra hallazgos sobre el corpus limpio."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path("scripts").resolve()))

from static_analysis import JavaScriptAnalyzer, TypeScriptAnalyzer

root = Path("tests/fixtures/benchmark/clean")
js = JavaScriptAnalyzer()
ts = TypeScriptAnalyzer()
for p in sorted(root.rglob("*")):
    if p.suffix in (".js", ".ts", ".tsx"):
        analyzer = js if p.suffix == ".js" else ts
        result = analyzer.analyze_file(str(p))
        for f in result.findings:
            print("FP?", p.name, f.rule_id, f.category, "line", f.line, "|", p.read_text().splitlines()[f.line - 1].strip() if f.line else "")
