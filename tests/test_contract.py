import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

class ContractTests(unittest.TestCase):
    def test_legacy_fields_match_original_schema(self):
        from security_auditor.engine import analyze
        from security_auditor.reporting import legacy_report, validate_report
        schema = json.loads((ROOT / 'tests/baseline-report.schema.json').read_text())
        with tempfile.TemporaryDirectory() as td:
            p = Path(td); (p / 'app.py').write_text('eval(input())')
            original = analyze(p, mode='STANDARD')
            old = legacy_report(original); validate_report(old)
            self.assertNotIn('analysis', old)
            self.assertIn('analysis', original)
            self.assertFalse(set(old) - set(schema['properties']))
            for f in old['findings']:
                props = schema['$defs']['finding']['properties']
                self.assertFalse(set(f) - set(props))
                for key in ('location', 'evidence', 'verification'):
                    self.assertFalse(set(f[key]) - set(props[key]['properties']))

    def test_early_returns_and_local_imports(self):
        from security_auditor.contextual import analyze_python
        sources = [
            'def choose(x):\n    if flag:\n        return x\n    return "2+2"\neval(choose(input()))',
            'def run():\n    import subprocess as s\n    s.run(input(), shell=True)',
        ]
        for source in sources:
            with self.subTest(source=source):
                f = analyze_python(source, 'fixture.py', [], mode='DEEP')
                self.assertTrue(any(x['status'] == 'PROBABLE' for x in f))

    def test_nan_and_infinite_budgets_rejected(self):
        from security_auditor.engine import analyze
        for value in (float('nan'), float('inf')):
            with self.assertRaises(ValueError): analyze(ROOT, max_seconds=value)

    def test_worker_timeout_and_memory_budget(self):
        from security_auditor.isolation import isolated_python
        limits = []
        self.assertEqual(isolated_python('eval(input())', 'x.py', limits,
            max_memory_bytes=1, seconds=1), [])
        self.assertTrue(limits)
        limits = []
        self.assertEqual(isolated_python('eval(input())', 'x.py', limits,
            seconds=0.000001), [])
        self.assertTrue(limits)

    def test_jwt_signature_and_query_trace(self):
        from security_auditor.contextual import analyze_python
        from precision_cases import CASES
        findings = analyze_python('import jwt\njwt.decode(input(), options={"verify_signature": False})', 'jwt.py', [])
        self.assertTrue(any(f['category'] == 'jwt-signature' and f['status'] == 'PROBABLE' for f in findings))
        text = next(c[-1] for c in CASES if c[0] == 'E22_client_tenant')
        findings = analyze_python(text, 'auth.py', [])
        f = next(f for f in findings if f['category'] == 'resource-authorization')
        self.assertTrue(f['evidence']['source'])

    def test_cli_modes_and_legacy_export(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); repo=base/'target'; repo.mkdir(); (repo/'app.py').write_text('eval(input())')
            for mode in ('QUICK','STANDARD','DEEP'):
                output=base/mode
                r=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/audit.py'),'scan',str(repo),'--output',str(output),'--mode',mode],capture_output=True,timeout=30)
                self.assertEqual(r.returncode,0,r.stderr)
                report=json.loads((output/'audit.json').read_text(encoding='utf-8'))
                self.assertEqual(report['analysis']['mode'],mode)
            r=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/audit.py'),'scan',str(repo),'--output',str(base/'legacy'),'--legacy-report'],capture_output=True,timeout=30)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertNotIn('analysis',json.loads((base/'legacy/audit.json').read_text(encoding='utf-8')))

    def test_budget_failure_is_reported_without_success_claim(self):
        from security_auditor.engine import analyze
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'app.py').write_text('eval(input())')
            report=analyze(root, mode='STANDARD', max_memory_bytes=1)
            self.assertEqual(report['findings'], [])
            self.assertTrue(any('memoria' in x for x in report['limitations']))
            self.assertTrue(all(t['status'] != 'executed' for t in report['tools'] if t['name']=='python-ast'))

    def test_rebound_identity_and_abort_are_not_security_controls(self):
        from security_auditor.contextual import analyze_python
        from precision_cases import route
        cases=[
            'current_user = lookup_user(request.args["user"])\nreturn Record.query.filter_by(id=resource_id, owner_id=current_user.id).first()',
            'abort = print\nobj = Record.query.get(resource_id)\nif obj.owner_id != current_user.id:\n    abort(403)\nreturn obj',
        ]
        for body in cases:
            with self.subTest(body=body):
                findings=analyze_python(route(body),'auth.py',[])
                self.assertFalse(any(f['category']=='resource-authorization' and f['status']=='FALSE_POSITIVE' for f in findings))

    def test_evaluation_arithmetic(self):
        from evaluate_precision import metrics
        result = metrics([{'label':True,'prediction':True}, {'label':False,'prediction':True},
                          {'label':True,'prediction':False}, {'label':False,'prediction':False},
                          {'label':None,'prediction':False}])
        self.assertEqual((result['tp'], result['fp'], result['fn'], result['tn']), (1,1,1,1))
        self.assertEqual((result['precision'], result['recall'], result['f1']), (.5,.5,.5))
        self.assertEqual(result['unlabeled'], 1)

if __name__ == '__main__': unittest.main()
