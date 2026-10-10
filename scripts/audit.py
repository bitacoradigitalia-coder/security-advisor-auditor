#!/usr/bin/env python3
"""Offline CLI. python scripts/audit.py --help"""
import argparse
import json
from pathlib import Path
import sys
import zipfile

sys.dont_write_bytecode = True
from security_auditor.engine import analyze
from security_auditor.reporting import write_outputs
from security_auditor.safeio import extract_zip, read_bounded
from security_auditor.scanners import plans
from security_auditor.validation import validate_skill


def main(argv=None):
    parser = argparse.ArgumentParser(description='Security Advisor Auditor v2.0: triaje estático local')
    commands = parser.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('scan', help='Inventario y candidatos; no ejecuta el repositorio')
    scan.add_argument('repository', type=Path); scan.add_argument('--output', type=Path, required=True)
    scan.add_argument('--max-file-bytes', type=int, default=1_000_000)
    scan.add_argument('--max-files', type=int, default=10000)
    scan.add_argument('--max-total-bytes', type=int, default=20_000_000)
    validate = commands.add_parser('validate-skill'); validate.add_argument('skill', type=Path)
    report = commands.add_parser('report', help='Validar y convertir audit.json revisado')
    report.add_argument('json_file', type=Path); report.add_argument('--output', type=Path, required=True)
    extract = commands.add_parser('extract-zip'); extract.add_argument('archive', type=Path)
    extract.add_argument('--output', type=Path, required=True)
    commands.add_parser('tools', help='Disponibilidad y condiciones de integraciones opcionales')
    args = parser.parse_args(argv)
    try:
        if args.command == 'scan':
            data = analyze(args.repository, args.max_file_bytes, args.max_files, args.max_total_bytes)
            write_outputs(data, args.output, args.repository)
            print('Informe generado; candidatos pendientes de verificación: ' + str(len(data['findings'])))
        elif args.command == 'validate-skill': print(json.dumps(validate_skill(args.skill), ensure_ascii=False))
        elif args.command == 'tools': print(json.dumps(plans(), ensure_ascii=False, indent=2))
        elif args.command == 'extract-zip':
            extract_zip(args.archive, args.output); print('Extracción completada en destino nuevo')
        elif args.command == 'report':
            data = json.loads(read_bounded(args.json_file, 20_000_000))
            write_outputs(data, args.output); print('Informe validado y generado')
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        # Do not echo source data, paths or malformed JSON that might contain secrets.
        print('Operación rechazada (' + type(exc).__name__ + '). Comprueba formato, permisos, límites y destino nuevo.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__': raise SystemExit(main())
