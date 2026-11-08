"""Parches v2 post-restauracion.

1) RuleEngine: soportar reglas que deben evaluar comentarios (scan_comments).
2) TS002 (@ts-ignore) marca scan_comments=True.
3) AIEngine: accion recomendada de falso positivo menciona "falso positivo".
"""
from pathlib import Path


def load_lines(path):
    return Path(path).read_text().splitlines()


def save_lines(path, lines):
    Path(path).write_text(chr(10).join(lines) + chr(10))


def patch_regex_rules():
    path = "scripts/static_analysis/regex_rules.py"
    lines = load_lines(path)
    if any("scan_comments: bool" in ln for ln in lines):
        print("regex_rules: ya parcheado")
        return
    out = []
    inserted_field = False
    for i, ln in enumerate(lines):
        out.append(ln)
        if ln == "    case_insensitive: bool = False":
            out.append("    scan_comments: bool = False")
            inserted_field = True
    if not inserted_field:
        raise SystemExit("regex_rules: campo case_insensitive no encontrado")
    old_if = '            if not stripped or stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):'.replace(chr(34), chr(34))
    idx = None
    for i, ln in enumerate(out):
        if ln.strip().startswith("if not stripped or stripped.startswith"):
            idx = i
            break
    if idx is None:
        raise SystemExit("regex_rules: bloque de salto de comentarios no encontrado")
    del out[idx:idx + 3]
    new_block = [
        "            if not stripped:",
        "                continue",
        "            is_comment = stripped.startswith(" + chr(34) + "//" + chr(34) + ") or stripped.startswith(" + chr(34) + "*" + chr(34) + ") or stripped.startswith(" + chr(34) + "/*" + chr(34) + ")",
        "            for rule in self.rules:",
        "                if is_comment and not rule.scan_comments:",
        "                    continue",
    ]
    out[idx:idx] = new_block
    save_lines(path, out)
    print("regex_rules: scan_comments anadido")


def patch_ts_analyzer():
    path = "scripts/static_analysis/ts_analyzer.py"
    lines = load_lines(path)
    if any(ln.strip() == "scan_comments=True," for ln in lines):
        print("ts_analyzer: ya parcheado")
        return
    out = []
    in_ts002 = False
    done = False
    for ln in lines:
        if "Rule(" == ln.strip():
            in_ts002 = False
        if "rule_id=" + chr(34) + "TS002" + chr(34) in ln:
            in_ts002 = True
        if in_ts002 and not done and ln.strip() == "tags=[" + chr(34) + "typescript" + chr(34) + "],":
            out.append("        scan_comments=True,")
            done = True
        out.append(ln)
    if not done:
        raise SystemExit("ts_analyzer: bloque TS002 no encontrado")
    save_lines(path, out)
    print("ts_analyzer: TS002 con scan_comments")


def patch_ai_engine():
    path = "scripts/core/ai_engine.py"
    lines = load_lines(path)
    out = []
    done = False
    for ln in lines:
        if "recommended_action=" in ln and "Cerrar el hallazgo y registrar" in ln:
            indent = ln[:len(ln) - len(ln.lstrip())]
            ln = indent + "recommended_action=" + chr(34) + "Cerrar el hallazgo (falso positivo) y registrar la justificacion" + chr(34) + ","
            done = True
        out.append(ln)
    if not done:
        print("ai_engine: accion FP ya parcheada o no encontrada")
    else:
        save_lines(path, out)
        print("ai_engine: accion FP actualizada")


patch_regex_rules()
patch_ts_analyzer()
patch_ai_engine()
