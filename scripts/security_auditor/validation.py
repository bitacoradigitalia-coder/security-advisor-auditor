"""Validator for this package's deliberately restricted YAML profile (not general YAML)."""
from pathlib import Path
import re

from .safeio import no_links, read_bounded, relative_name


def validate_skill(root):
    root = no_links(root)
    text = read_bounded(root / 'SKILL.md', 100_000).decode('utf-8-sig')
    match = re.match(r'\A---\r?\n(.*?)\r?\n---\r?\n', text, re.S)
    if not match: raise ValueError('Frontmatter requerido')
    values = {}; metadata = False
    for line in match[1].splitlines():
        if line == 'metadata:': metadata = True; continue
        if line.startswith('  ') and metadata:
            if not re.fullmatch(r'  [\w/-]+: "[^"\n]+"', line): raise ValueError('metadata debe contener strings')
            continue
        metadata = False
        key, sep, value = line.partition(': ')
        if not sep or key in values or key not in ('name', 'description', 'license', 'compatibility'):
            raise ValueError('Campo no admitido en perfil portable: ' + key)
        if value.startswith('"'):
            import json
            value = json.loads(value)
            if not isinstance(value, str): raise ValueError('Se requiere string YAML')
        elif ': ' in value or re.search(r'[\[\]{}#&*!|>]', value):
            raise ValueError('Escalar YAML complejo: usar string entre comillas')
        values[key] = value
    name = values.get('name', '')
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', name) or len(name) > 64 or name != root.name:
        raise ValueError('Nombre no válido o distinto de carpeta')
    if not 1 <= len(values.get('description', '')) <= 1024: raise ValueError('Descripción inválida')
    if 'compatibility' in values and not 1 <= len(values['compatibility']) <= 500: raise ValueError('Compatibilidad inválida')
    for md in [root / 'SKILL.md', *sorted((root / 'references').glob('*.md'))]:
        body = read_bounded(md, 100_000).decode('utf-8-sig')
        for dest in re.findall(r'\[[^\]]+\]\(([^)]+)\)', body):
            if dest.startswith(('https://', 'http://', '#')): continue
            rel = relative_name(dest.split('#')[0])
            if not (root / rel).is_file(): raise ValueError('Referencia ausente: ' + str(rel))
    method = read_bounded(root / 'references/audit-methodology.md', 100_000).decode('utf-8-sig')
    audit_section = method.split('# AUDIT METHODOLOGY\n', 1)[-1].split('# REQUIRED DEEP-REASONING CHECKS', 1)[0]
    if [int(x) for x in re.findall(r'^## Phase (\d+) —', audit_section, re.M)] != list(range(1, 22)):
        raise ValueError('Las 21 fases deben mantenerse')
    return {'valid': True, 'name': name, 'phases': 21, 'profile': 'portable YAML subset; not a general YAML parser'}
