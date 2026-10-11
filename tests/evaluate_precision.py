"""Reproducible evaluation of synthetic fixtures. Does not execute fixture code."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from baseline_v201 import python_candidates
from precision_cases import CASES
from security_auditor.contextual import RULES
from security_auditor.engine import analyze
from security_auditor.reporting import validate_report


def metrics(rows):
    labeled = [r for r in rows if r['label'] is not None]
    tp = sum(r['label'] and r['prediction'] for r in labeled)
    fp = sum(not r['label'] and r['prediction'] for r in labeled)
    fn = sum(r['label'] and not r['prediction'] for r in labeled)
    tn = sum(not r['label'] and not r['prediction'] for r in labeled)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall,
                f1=2*precision*recall/(precision+recall) if precision+recall else 0.0,
                labeled=len(labeled), unlabeled=len(rows)-len(labeled))


def evaluate():
    results = []
    for name, group, category, unsafe, status, code in CASES:
        fixture = (ROOT/'tests/fixtures'/name/'app.py').read_text(encoding='utf-8')
        if fixture != code+'\n': raise ValueError('Fixture/expectation mismatch: '+name)
        limits = []
        previous = python_candidates(code, 'fixture.py', [])
        report = analyze(ROOT/'tests/fixtures'/name, mode='STANDARD')
        validate_report(report)
        current = report['findings']; limits = report['limitations']
        relevant = [f for f in current if f['category'] == category]
        original = [f for f in previous if f['cwe'] == RULES[category][1]]
        obtained = sorted({f['status'] for f in relevant})
        results.append({'case':name, 'group':group, 'language':'Python',
            'framework':'Flask/Flask-Login query shape' if group == 'authorization' else 'stdlib/library call shape',
            'category':category, 'label':unsafe, 'expected_states': [] if status is None else [status],
            'obtained_states':obtained, 'correct_state': obtained == ([] if status is None else [status]),
            'v201_alert':bool(original), 'v21_alert':any(f['status'] in ('PROBABLE','CONFIRMED') for f in relevant),
            'findings':relevant, 'limitations':limits})
    def rows(version): return [dict(label=r['label'], prediction=r[version+'_alert']) for r in results]
    return {'scope':'Synthetic fixture set only; not general product precision. No fixture executed.',
        'baseline_commit':'51a3abb390b799a13baceb0cfb922e8786e4d6ac',
        'baseline_sha256':hashlib.sha256((ROOT/'tests/baseline_v201.py').read_bytes()).hexdigest(),
        'versions': {v:metrics(rows(v)) for v in ('v201','v21')},
        'by_category':{c: {v:metrics([dict(label=r['label'],prediction=r[v+'_alert']) for r in results if r['category']==c]) for v in ('v201','v21')} for c in sorted({r['category'] for r in results})},
        'by_language':{'Python':{v:metrics(rows(v)) for v in ('v201','v21')}},
        'by_framework':{fw:{v:metrics([dict(label=r['label'], prediction=r[v+'_alert']) for r in results if r['framework']==fw]) for v in ('v201','v21')} for fw in sorted({r['framework'] for r in results})},
        'state_accuracy':sum(r['correct_state'] for r in results)/len(results),
        'results':results}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path)
    args = parser.parse_args(); result = evaluate()
    if args.output:
        if args.output.exists(): raise ValueError('Evaluation destination already exists')
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'versions':result['versions'], 'state_accuracy':result['state_accuracy']}, indent=2))
    return 0 if result['state_accuracy'] == 1 else 1

if __name__ == '__main__': raise SystemExit(main())
