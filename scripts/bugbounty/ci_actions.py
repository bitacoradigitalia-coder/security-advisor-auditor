"""Acciones de Bug Bounty usadas por el workflow manual (workflow_dispatch)."""

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from bugbounty.manager import BugBountyManager


def _write(name, text):
    out_dir = "reports/bugbounty"
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
        f.write(text)
    print(text)


def main():
    action = os.environ.get("ACTION", "")
    program_name = os.environ.get("PROGRAM_NAME", "")
    manager = BugBountyManager()

    if action == "list-programs":
        programs = manager.list_programs()
        _write("programs.txt", chr(10).join(programs) if programs else "No hay programas")

    elif action == "add-program":
        manager.add_program(
            name=program_name,
            scope=os.environ.get("PROGRAM_SCOPE", ""),
            platform=os.environ.get("PROGRAM_PLATFORM", "generic"),
            platform_handle=os.environ.get("PROGRAM_HANDLE", ""),
        )
        _write("add-program.txt", "Programa agregado: " + program_name)

    elif action == "list-findings":
        findings = manager.list_findings(program_name) if program_name else manager.list_all_findings()
        lines = ["[" + f.severity.upper() + "] " + f.id + ": " + f.title for f in findings]
        _write("findings.txt", chr(10).join(lines) if lines else "No hay hallazgos")

    elif action in ("generate-report", "submit-report"):
        fmt = os.environ.get("REPORT_FORMAT") or "markdown"
        report = manager.generate_report(os.environ.get("FINDING_ID", ""), format=fmt)
        _write("report." + fmt, report)

    else:
        print("Accion desconocida: " + action)
        raise SystemExit(1)


if __name__ == "__main__":
    main()