"""Parche puntual v2.2: corregir el patron JS006 de js_analyzer.py.

El patron original contenia comillas sin escapar dentro de una cadena raw
delimitada por comillas dobles, lo que provocaba un SyntaxError al importar.
Se reescribe usando escapes hexadecimales para que sea identico pero valido.
"""
from pathlib import Path

NEW_LINE = ("        pattern=r" + chr(34) + "(SELECT|INSERT|UPDATE|DELETE)"
          + chr(92) + "[^" + chr(92) + "x22" + chr(92) + "x27]*[" + chr(92) + "x22" + chr(92) + "x27]?"
          + chr(92) + "s*" + chr(92) + "+|" + chr(92) + "+s*" + chr(92) + "s*[" + chr(92) + "x22" + chr(92) + "x27]" + chr(92) + "s*"
          + chr(34) + ',")'

p = Path("scripts/static_analysis/js_analyzer.py")
src = p.read_text()
lines = src.splitlines()
fixed = False
for i, ln in enumerate(lines):
    if "(SELECT|" in ln and ln.lstrip().startswith("pattern=r" + chr(34) + "(SELECT|"):
        lines[i] = NEW_LINE
        fixed = True
        break
if not fixed:
    raise SystemExit("fix_js006: linea del patron JS006 no encontrada")
p.write_text(chr(10).join(lines) + chr(10))
print("fix_js006: patron JS006 corregido")
