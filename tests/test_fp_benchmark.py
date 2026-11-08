"""Benchmark de falsos positivos (mejora 2 del plan v2.2).

Criterio de la FASE 2: la tasa de falsos positivos de los analizadores
nativos JS/TS debe mantenerse por debajo del 10% sobre un corpus
determinista versionado en el repositorio.

Metrica: FP / (FP + TP) donde:
- FP: hallazgos sobre el corpus LIMPIO (codigo seguro de referencia)
- TP: hallazgos sobre el corpus VULNERABLE

El corpus vive en tests/fixtures/benchmark/{clean,vulnerable}/.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from static_analysis import JavaScriptAnalyzer, TypeScriptAnalyzer

BENCHMARK_ROOT = Path(__file__).resolve().parent / "fixtures" / "benchmark"
FP_THRESHOLD = 0.10


def _count(analyzer, directory):
    result = analyzer.analyze_directory(directory)
    if not result.success:
        raise AssertionError("el analizador fallo en " + str(directory))
    return len(result.findings)


def benchmark_rate():
    js = JavaScriptAnalyzer()
    ts = TypeScriptAnalyzer()
    fp = _count(js, BENCHMARK_ROOT / "clean" / "js") + _count(ts, BENCHMARK_ROOT / "clean" / "ts")
    tp = _count(js, BENCHMARK_ROOT / "vulnerable" / "js") + _count(ts, BENCHMARK_ROOT / "vulnerable" / "ts")
    rate = (fp / (fp + tp)) if (fp + tp) else 1.0
    return fp, tp, rate


class TestBenchmarkFalsosPositivos(unittest.TestCase):
    """Mejora 2: criterio FASE 2 medido en CI de forma determinista."""

    def test_corpus_existe(self):
        clean = [p for p in (BENCHMARK_ROOT / "clean").rglob("*") if p.is_file()]
        vuln = [p for p in (BENCHMARK_ROOT / "vulnerable").rglob("*") if p.is_file()]
        self.assertGreaterEqual(len(clean), 6, "corpus limpio incompleto")
        self.assertGreaterEqual(len(vuln), 8, "corpus vulnerable incompleto")

    def test_tasa_fp_menor_del_10pct(self):
        fp, tp, rate = benchmark_rate()
        detail = "FP=" + str(fp) + " TP=" + str(tp) + " tasa=" + str(round(rate * 100, 2)) + "%"
        self.assertGreater(tp, 0, "el corpus vulnerable no produce hallazgos: " + detail)
        self.assertLess(rate, FP_THRESHOLD, "tasa de falsos positivos >= 10%: " + detail)

    def test_detalle_por_directorio(self):
        fp, tp, rate = benchmark_rate()
        self.assertTrue(fp + tp > 0)
        self.assertGreaterEqual(fp, 0)


if __name__ == "__main__":
    unittest.main()
