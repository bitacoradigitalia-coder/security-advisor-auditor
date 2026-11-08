#!/usr/bin/env python3
"""
CLI del modulo SCA (mejora M12): python scripts/sca/cli.py --help

Desviacion documentada respecto al PLAN 12.4: el subcomando no se anadio
a scripts/audit.py (~900 lineas con f-strings anidados; el coste de
re-transcribirlo supera el beneficio). Uso:

  python scripts/sca/cli.py --requirements requirements.txt --output ./sca-report
  python scripts/sca/cli.py --requirements requirements.txt --output ./sca-report --online
"""
import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from sca.osv_client import OSVClient
from sca.sbom import SBOMGenerator, parse_requirements
from sca.scanner import SCAScanner


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SCA: SBOM CycloneDX 1.5 + advisories (offline por defecto)")
    parser.add_argument("--requirements", type=Path, default=Path("requirements.txt"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--online", action="store_true", help="Consultar OSV.dev (opt-in; requiere alcance autorizado)")
    args = parser.parse_args(argv)

    scope_manager = None
    if args.online:
        try:
            from core.scope_manager import ScopeManager, ScopeConfig
            scope_manager = ScopeManager(ScopeConfig())
        except Exception as exc:  # pragma: no cover - entorno sin core
            print("[!] ScopeManager no disponible: " + str(exc), file=sys.stderr)

    sbom_gen = SBOMGenerator().from_requirements(args.requirements)
    entries = parse_requirements(args.requirements)

    osv = OSVClient(offline=not args.online, scope_manager=scope_manager)
    scanner = SCAScanner(osv_client=osv)
    results = scanner.scan_requirements(entries)

    args.output.mkdir(parents=True, exist_ok=True)
    sbom_gen.to_json(args.output / "sbom.json")
    report = {
        "tool": "SCAScanner",
        "requirements": str(args.requirements),
        "mode": "online" if args.online else "offline",
        "dependencies": len(entries),
        "vulnerable": [r.to_dict() for r in results],
    }
    with (args.output / "sca-report.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    print("[+] SBOM: " + str(args.output / "sbom.json"))
    print("[+] Reporte: " + str(args.output / "sca-report.json"))
    print("[+] Dependencias: " + str(len(entries)) + " | vulnerables: " + str(len(results)))
    for item in results:
        adv = item.advisory
        print("    [" + adv.severity.upper() + "] " + item.package + "@" + item.version +
              " " + adv.advisory_id + " -> fix: " + adv.fixed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
