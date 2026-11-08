"""Mejora 4: afin de reglas JS para reducir falsos positivos.

- JS006: patron SQLi mal construido (disparaba con cualquier concatenacion)
- JS009: excluir hosts de specs (w3.org, openid.net, xmlsoap.org, purl.org)
- JS013: severidad low -> info (es informativo)
- JS016 nueva: redireccion abierta (open redirect)
- JS017 nueva: setTimeout/setInterval con string de codigo
"""
from pathlib import Path

Q = chr(34)
BS = chr(92)

JS006_PAT = ("        pattern=r" + Q + "(SELECT|INSERT|UPDATE|DELETE)"
             + BS + "[^" + BS + "x22" + BS + "x27]*[" + BS + "x22" + BS + "x27]?"
             + BS + "s*" + BS + "+|" + BS + "+" + BS + "s*[" + BS + "x22" + BS + "x27]"
             + BS + "s*(SELECT|INSERT|UPDATE|DELETE)" + Q + ",")

JS009_PAT = ("        pattern=r" + Q + "http://(?!localhost|127" + BS + ".0" + BS + ".0" + BS + ".1"
             + "|www" + BS + ".w3" + BS + ".org|schema" + BS + ".w3" + BS + ".org"
             + "|www" + BS + ".openid" + BS + ".net|schemas" + BS + ".xmlsoap" + BS + ".org"
             + "|purl" + BS + ".org)" + Q + ",")

JS016_PAT = ("        pattern=r" + Q + "(location" + BS + ".(href|replace|assign)|window" + BS + ".open)"
             + BS + "s*[" + BS + "=(][^;]*(request|params|query|input|target|user)" + Q + ",")

JS017_PAT = ("        pattern=r" + Q + "set(Timeout|Interval)" + BS + "(" + BS + "s*["
             + BS + "x22" + BS + "x27]" + Q + ",")

NEW_RULES = [
    "    Rule(",
    '        rule_id="JS016",',
    '        title="Posible redireccion abierta (open redirect)",',
    '        category="open_redirect",',
    '        severity="medium",',
    '        confidence="medium",',
    'NEW_RULE_JS016',
    '        message="Redireccion con destino derivado de datos externos permite open redirect y phishing",',
    '        remediation="Validar el destino contra una lista blanca antes de redirigir",',
    '        tags=["owasp:a01", "dom"],',
    "    ),",
    "    Rule(",
    '        rule_id="JS017",',
    '        title="setTimeout/setInterval con string de codigo",',
    '        category="rce",',
    '        severity="high",',
    '        confidence="medium",',
    'NEW_RULE_JS017',
    '        message="setTimeout con string equivale a eval y ejecuta codigo dinamicamente",',
    '        remediation="Pasar una funcion en lugar de un string a setTimeout/setInterval",',
    '        tags=["owasp:a03"],',
    "    ),",
]
NEW_RULES = [ln.replace("NEW_RULE_JS016", JS016_PAT).replace("NEW_RULE_JS017", JS017_PAT) for ln in NEW_RULES]

p = Path("scripts/static_analysis/js_analyzer.py")
src_lines = p.read_text().splitlines()
out = []
in_js013 = False
changed = []
for ln in src_lines:
    stripped = ln.strip()
    if stripped == "Rule(":
        in_js013 = False
    if ln.lstrip().startswith("pattern=r" + Q + "(SELECT|"):
        out.append(JS006_PAT)
        changed.append("JS006")
        continue
    if "http://(?!localhost" in ln:
        out.append(JS009_PAT)
        changed.append("JS009")
        continue
    if in_js013 and stripped == 'severity="low",':
        out.append(ln[:len(ln) - len(ln.lstrip())] + 'severity="info",')
        changed.append("JS013")
        continue
    if stripped == 'rule_id="JS013",':
        in_js013 = True
    if ln == "]" and "JS016" not in changed:
        out.extend(NEW_RULES)
        changed.append("JS016/JS017")
    out.append(ln)

if "JS006" not in changed or "JS009" not in changed or "JS013" not in changed or "JS016/JS017" not in changed:
    raise SystemExit("fix_rules_v3: cambios incompletos: " + ", ".join(changed))
p.write_text(chr(10).join(out) + chr(10))
print("fix_rules_v3 aplicado: " + ", ".join(changed))
