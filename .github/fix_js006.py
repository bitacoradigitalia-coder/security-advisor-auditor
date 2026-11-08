"""Parche puntual v2.2: corregir el patron JS006 de js_analyzer.py.

El patron original contenia comillas sin escapar dentro de una cadena raw
delimitada por comillas dobles, lo que provocaba un SyntaxError al importar.
Se reescribe usando \x22/\x27 para que el patron sea identico pero valido.
"""
from pathlib import Path

p = Path("scripts/static_analysis/js_analyzer.py")
src = p.read_text()
lines = src.split("
")
fixed = False
for i, ln in enumerate(lines):
    if ln.lstrip().startswith('pattern=r"(SELECT|'):
        lines[i] = '        pattern=r"(SELECT|INSERT|UPDATE|DELETE)[^\\x22\\x27]*[\\x22\\x27]?\\s*\\+|\\+\\s*[\\x22\\x27]\\s*(SELECT|INSERT|UPDATE|DELETE)",'
        fixed = True
        break
if not fixed:
    raise SystemExit("fix_js006: linea del patron JS006 no encontrada")
p.write_text("
".join(lines))
print("fix_js006: patron JS006 corregido")
