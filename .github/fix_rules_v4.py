"""Mejora 4 (v4): JS006 sin backslash delante de la clase de caracteres.

v3 dejo "\[^"']" (corchete escapado) en lugar de "[^"']",
por lo que la regla SQLi dejaba de detectar el caso clasico.
"""
from pathlib import Path

Q = chr(34)
BS = chr(92)

OLD_MARK = "(SELECT|INSERT|UPDATE|DELETE)" + BS + "[^"
NEW_LINE = ("        pattern=r" + Q + "(SELECT|INSERT|UPDATE|DELETE)[^"
             + BS + "x22" + BS + "x27]*[" + BS + "x22" + BS + "x27]?"
             + BS + "s*" + BS + "+|" + BS + "+" + BS + "s*[" + BS + "x22" + BS + "x27]"
             + BS + "s*(SELECT|INSERT|UPDATE|DELETE)" + Q + ",")

p = Path("scripts/static_analysis/js_analyzer.py")
lines = p.read_text().splitlines()
fixed = False
for i, ln in enumerate(lines):
    if OLD_MARK in ln and ln.lstrip().startswith("pattern=r"):
        lines[i] = NEW_LINE
        fixed = True
if not fixed:
    print("fix_rules_v4: ya parcheado, nada que hacer")
else:
    p.write_text(chr(10).join(lines) + chr(10))
    print("fix_rules_v4: patron JS006 corregido")
