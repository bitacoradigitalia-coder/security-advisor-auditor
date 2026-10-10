#!/usr/bin/env python3
"""Explicit file installation; never edits client configs or executes client binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from security_auditor.safeio import no_links, read_bounded, relative_name, remove_owned_tree
from security_auditor.validation import validate_skill

NAME = 'security-advisor-auditor'
MANIFEST = '.saa-install.json'
DIRECTORIES = {'scripts', 'references', 'modules', 'agents', 'assets', 'schemas', 'adapters',
               'docs', 'examples', 'tests'}
FILES = {'SKILL.md', 'README.md', 'LICENSE', 'CHANGELOG.md', 'install.py'}


def payload():
    validate_skill(ROOT)
    result = {}
    for name in sorted(FILES):
        result[name] = read_bounded(ROOT / name, 2_000_000)
    for dirname in sorted(DIRECTORIES):
        base = no_links(ROOT / dirname)
        if not base.is_dir(): continue
        for folder, dirs, files in os.walk(base, followlinks=False):
            for name in dirs + files: no_links(Path(folder) / name)
            dirs[:] = [d for d in dirs if d != '__pycache__']
            for name in sorted(files):
                if name.endswith(('.pyc', '.pyo')): continue
                path = Path(folder) / name
                relative = path.relative_to(ROOT).as_posix()
                relative_name(relative)
                result[relative] = read_bounded(path, 2_000_000)
    if len(result) > 1000 or sum(map(len, result.values())) > 20_000_000:
        raise ValueError('Paquete excede límites')
    return result


def allowed_file(name):
    rel = relative_name(name)
    if name not in FILES and rel.parts[0] not in DIRECTORIES:
        raise ValueError('Archivo fuera del paquete')
    if '.git' in rel.parts: raise ValueError('Metadatos Git no permitidos')
    return rel


def installed_manifest(destination, agent):
    no_links(destination)
    if not destination.is_dir(): raise ValueError('Instalación no encontrada')
    data = json.loads(read_bounded(destination / MANIFEST, 200_000))
    if data.get('name') != NAME or data.get('agent') != agent or data.get('format') != 1:
        raise ValueError('Instalación no administrada por este perfil')
    hashes = data.get('files')
    if not isinstance(hashes, dict) or not 1 <= len(hashes) <= 1000 or 'SKILL.md' not in hashes:
        raise ValueError('Manifest inválido')
    expected_dirs = set()
    for name, digest in hashes.items():
        rel = allowed_file(name)
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Hash no válido')
        for parent in rel.parents:
            if parent != Path('.'): expected_dirs.add(parent.as_posix())
        content = read_bounded(destination / rel, 2_000_000)
        if hashlib.sha256(content).hexdigest() != digest: raise ValueError('Archivo modificado; se conserva')
    actual = set(); count = 0
    for folder, dirs, files in os.walk(destination, followlinks=False):
        for name in dirs + files:
            count += 1
            if count > 5000: raise ValueError('Demasiadas entradas instaladas')
            path = Path(folder) / name; no_links(path)
            relative = path.relative_to(destination).as_posix()
            if name in dirs and relative not in expected_dirs: raise ValueError('Directorio ajeno; se conserva')
            if name in files: actual.add(relative)
    if actual != set(hashes) | {MANIFEST}: raise ValueError('Archivos ajenos; se conservan')
    return data


def operate(agent, skills_dir, dry_run=False, uninstall=False, update=False):
    directory = no_links(skills_dir)
    destination = directory / NAME
    no_links(destination)
    if destination.resolve() == ROOT or destination.resolve().is_relative_to(ROOT):
        raise ValueError('No instalar sobre/dentro del paquete fuente')
    exists = os.path.lexists(destination)
    if uninstall or update:
        if not exists: raise ValueError('No hay instalación para actualizar/desinstalar')
        installed_manifest(destination, agent)
    elif exists: raise ValueError('Destino existente; usa --update para instalación administrada intacta')
    contents = None if uninstall else payload()
    if dry_run: return {'status': 'dry_run', 'destination': str(destination), 'agent': agent,
                         'operation': 'uninstall' if uninstall else 'update' if update else 'install'}
    if uninstall:
        # Integrity was checked before removal. Delete only this fixed child folder.
        remove_owned_tree(destination)
        return {'status': 'uninstalled', 'agent': agent, 'destination': str(destination)}
    directory.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.saa-install-', dir=directory))
    backup = None
    try:
        hashes = {}
        for name, content in contents.items():
            target = staging / allowed_file(name); target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as out: out.write(content)
            hashes[name] = hashlib.sha256(read_bounded(target, 2_000_000)).hexdigest()
            if hashes[name] != hashlib.sha256(content).hexdigest(): raise ValueError('Integridad de copia fallida')
        manifest = {'format': 1, 'name': NAME, 'agent': agent, 'version': '2.0.0', 'files': hashes}
        (staging / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        if update:
            installed_manifest(destination, agent)
            # Reserve a unique sibling name, then preserve old installation until new one is published.
            backup = Path(tempfile.mkdtemp(prefix='.saa-backup-', dir=directory)); backup.rmdir()
            destination.rename(backup)
        elif os.path.lexists(destination): raise ValueError('Destino creado durante instalación')
        try: staging.rename(destination)
        except OSError:
            if backup is not None and not destination.exists(): backup.rename(destination); backup = None
            raise
        installed_manifest(destination, agent)
        if backup is not None: remove_owned_tree(backup); backup = None
    finally:
        if staging.exists(): remove_owned_tree(staging)
    return {'status': 'updated' if update else 'installed', 'agent': agent,
            'destination': str(destination), 'files_verified': len(contents), 'runtime_verified': False}


def main(argv=None):
    profiles = json.loads(read_bounded(ROOT / 'adapters/profiles.json', 100_000))
    parser = argparse.ArgumentParser(description='Instalador local con verificación SHA256')
    parser.add_argument('--agent', required=True, choices=sorted(profiles))
    parser.add_argument('--skills-dir', type=Path, help='Directorio padre de skills explícito (no carpeta de la skill)')
    parser.add_argument('--dry-run', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--uninstall', action='store_true'); mode.add_argument('--update', action='store_true')
    args = parser.parse_args(argv)
    directory = args.skills_dir or Path.home().joinpath(*profiles[args.agent]['home_parts'])
    try:
        result = operate(args.agent, directory, args.dry_run, args.uninstall, args.update)
        result['os'] = platform.system(); result['python'] = platform.python_version()
        print(json.dumps(result, ensure_ascii=False, indent=2)); return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('Instalación rechazada: comprueba destino, enlaces, manifest y cambios locales. No se fuerza sobrescritura.', file=sys.stderr)
        return 2


if __name__ == '__main__': raise SystemExit(main())
