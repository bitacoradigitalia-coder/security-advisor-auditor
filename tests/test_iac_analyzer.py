"""
Tests del IaCAnalyzer (mejora M13): Dockerfile, K8s/compose, Terraform y
GitHub Actions, con fixtures versionados y casos negativos limpios.
"""
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = str(Path(__file__).resolve().parents[1] / "scripts")
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "iac"
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from static_analysis.iac_analyzer import IaCAnalyzer
from static_analysis import get_analyzer


class TestIaCAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = IaCAnalyzer()

    def _ids(self, path):
        return [f.id.split(":")[0] for f in self.analyzer.analyze_file(path)]

    def test_dockerfile(self):
        ids = self._ids(FIXTURES_DIR / "Dockerfile")
        for expected in ("DOCK001", "DOCK002", "DOCK003", "DOCK004"):
            self.assertIn(expected, ids)

    def test_dockerfile_limpio_sin_falsos_positivos(self):
        with tempfile.NamedTemporaryFile("w", suffix="", prefix="Dockerfile", delete=False) as handle:
            handle.write("FROM python:3.10.13\nRUN pip install requests\nUSER appuser\n")
            tmp = Path(handle.name)
        try:
            self.assertEqual(self.analyzer.analyze_file(tmp), [])
        finally:
            tmp.unlink()

    def test_compose(self):
        ids = self._ids(FIXTURES_DIR / "docker-compose.yml")
        self.assertIn("K8S001", ids)
        self.assertIn("K8S002", ids)

    def test_k8s(self):
        ids = self._ids(FIXTURES_DIR / "deployment.yaml")
        for expected in ("K8S001", "K8S002", "K8S004"):
            self.assertIn(expected, ids)
        # K8S003 (ausencia de runAsNonRoot con containers definidos)
        self.assertIn("K8S003", ids)

    def test_k8s_limpio(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      image: app:1.0\n      securityContext:\n        runAsNonRoot: true\n")
            tmp = Path(handle.name)
        try:
            self.assertEqual(self.analyzer.analyze_file(tmp), [])
        finally:
            tmp.unlink()

    def test_terraform(self):
        ids = self._ids(FIXTURES_DIR / "main.tf")
        for expected in ("TF001", "TF002", "TF003"):
            self.assertIn(expected, ids)

    def test_github_actions(self):
        ids = self._ids(FIXTURES_DIR / "workflow.yml")
        for expected in ("GHA001", "GHA002", "GHA003", "GHA004"):
            self.assertIn(expected, ids)

    def test_github_actions_limpio(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
            handle.write("name: CI\non:\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ok\n")
            tmp = Path(handle.name)
        try:
            self.assertEqual(self.analyzer.analyze_file(tmp), [])
        finally:
            tmp.unlink()

    def test_directorio(self):
        result = self.analyzer.analyze_directory(FIXTURES_DIR)
        self.assertTrue(result.success)
        self.assertGreater(len(result.findings), 10)
        self.assertEqual(result.statistics["files_scanned"], 5)

    def test_registro_en_get_analyzer(self):
        self.assertIsInstance(get_analyzer(tool="iac_native"), IaCAnalyzer)
        self.assertIsInstance(get_analyzer(language="terraform"), IaCAnalyzer)


if __name__ == "__main__":
    unittest.main()
