"""Trusted private parser entrypoint, started with -I -B and memory caps."""
import json
import os
from pathlib import Path
import sys
import time


def main():
    memory = int(sys.argv[1])
    if os.name != 'nt':
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from security_auditor.contextual import analyze_python
    from security_auditor.engine import scrub
    # Bound IPC input as well. The target's files are never opened from here.
    payload = sys.stdin.buffer.read(20_000_001)
    if len(payload) > 20_000_000: return 2
    data = json.loads(payload); limitations = []
    findings = analyze_python(data['text'], data['name'], limitations, mode=data['mode'],
        max_nodes=data['max_nodes'], max_memory_bytes=data['max_memory_bytes'],
        max_call_depth=data['max_call_depth'], deadline=time.perf_counter()+data['seconds'])
    if len(findings) > data['max_findings']:
        limitations.append('Límite de hallazgos alcanzado: ' + data['name'])
        findings = findings[:data['max_findings']]
    completed = not any(x.startswith(('AST no disponible', 'Presupuesto estimado', 'Límite de nodos/memoria', 'Límite de tiempo')) for x in limitations)
    sys.stdout.buffer.write(json.dumps(scrub(dict(findings=findings, limitations=limitations, completed=completed)), ensure_ascii=False).encode('utf-8'))
    return 0

if __name__ == '__main__': raise SystemExit(main())
