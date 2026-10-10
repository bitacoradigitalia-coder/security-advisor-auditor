"""Locate one source root by content; never import or run code from a source ZIP."""
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile

from .safeio import extract_zip, is_link, no_links, remove_owned_tree
from .validation import skill_metadata, validate_skill

NAME = 'security-advisor-auditor'
SKIP = {'.git', '.hg', '.svn', '__pycache__', 'node_modules', '.venv', 'venv'}


def find_project_root(directory, max_entries=10000, max_depth=16):
    directory = no_links(directory)
    if not directory.is_dir(): raise ValueError('Fuente debe ser directorio')
    candidates = []; pending = [(directory, 0)]; count = 0
    while pending:
        folder, depth = pending.pop()
        if depth > max_depth: raise ValueError('Fuente supera profundidad de detección')
        skill = folder / 'SKILL.md'; method = folder / 'references/audit-methodology.md'
        if skill.exists() and method.exists():
            no_links(skill); no_links(method)
            if skill_metadata(folder).get('name') == NAME:
                candidates.append(folder)
        with os.scandir(folder) as entries:
            for entry in entries:
                count += 1
                if count > max_entries: raise ValueError('Fuente supera límite de entradas')
                path = Path(entry.path)
                if is_link(path): raise ValueError('Fuente contiene enlace/reparse point')
                if entry.is_dir(follow_symlinks=False) and entry.name not in SKIP:
                    pending.append((path, depth + 1))
    if len(candidates) != 1:
        raise ValueError('Se requiere exactamente una raíz Security Advisor Auditor')
    root = candidates[0]
    validate_skill(root)
    return root


@contextmanager
def project_source(location):
    location = no_links(location)
    if location.is_dir():
        yield find_project_root(location)
        return
    if not location.is_file(): raise ValueError('Fuente debe ser carpeta o ZIP regular')
    # Archive filename is irrelevant. extract_zip rejects traversal, links,
    # ambiguous paths and bombs before any candidate can be installed.
    temporary = Path(tempfile.mkdtemp(prefix='saa-source-'))
    try:
        extracted = extract_zip(location, temporary / 'extracted')
        yield find_project_root(extracted)
    finally:
        if temporary.exists(): remove_owned_tree(temporary)
