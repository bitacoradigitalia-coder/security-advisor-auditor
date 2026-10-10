"""Bounded reads and portable path validation. No target code is executed."""
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import zipfile

EXCLUDED = {'.git', '.hg', '.svn', 'node_modules', '.venv', 'venv', '__pycache__',
            'dist', 'build', '.next', '.cache', '.terraform'}
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} | {
    f'{prefix}{n}' for prefix in ('COM', 'LPT') for n in range(1, 10)}


def is_link(path):
    """Reject symlinks and Windows junctions/reparse points, including broken links."""
    s = Path(path).lstat()
    return stat.S_ISLNK(s.st_mode) or bool(getattr(s, 'st_file_attributes', 0) & 0x400)


def no_links(path):
    path = Path(os.path.abspath(Path(path).expanduser()))
    for item in (path, *path.parents):
        if os.path.lexists(item) and is_link(item):
            raise ValueError('Enlace/reparse point rechazado')
    return path


def relative_name(name):
    """Validate names on every OS, not only the current OS."""
    if not isinstance(name, str) or not name or len(name) > 240:
        raise ValueError('Nombre de archivo inválido')
    if '\\' in name or re.search(r'[\x00-\x1f\x7f:<>"|?*]', name):
        raise ValueError('Ruta no portable')
    parts = name.split('/')
    if any(p in ('', '.', '..') or p.endswith((' ', '.')) or
           p.split('.')[0].upper() in RESERVED for p in parts):
        raise ValueError('Ruta peligrosa o reservada')
    return Path(*parts)


def read_bounded(path, limit):
    path = no_links(path)
    s = path.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_size > limit:
        raise ValueError('Archivo no regular o demasiado grande')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Archivo excede el límite')
    return data


def repository_files(root, limitations, max_files=10000, max_entries=50000, max_depth=64, deadline=None):
    root = no_links(root)
    if not root.is_dir():
        raise ValueError('El objetivo debe ser un directorio')
    count = entries = 0
    pending = [(root, 0)]
    while pending:
        folder, depth = pending.pop()
        if depth > max_depth:
            limitations.append('Profundidad máxima alcanzada'); continue
        try:
            with os.scandir(folder) as iterator:
                for entry in iterator:
                    if deadline is not None and time.perf_counter() > deadline:
                        limitations.append('Límite de tiempo durante inventario; entradas restantes no analizadas'); return
                    entries += 1
                    if entries > max_entries:
                        limitations.append('Límite de entradas alcanzado'); return
                    path = Path(entry.path)
                    if is_link(path):
                        limitations.append('Enlace omitido: ' + path.relative_to(root).as_posix()); continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in EXCLUDED:
                            limitations.append('Directorio excluido: ' + path.relative_to(root).as_posix())
                        else:
                            pending.append((path, depth + 1))
                    elif entry.is_file(follow_symlinks=False):
                        if count >= max_files:
                            limitations.append('Límite de archivos alcanzado'); return
                        count += 1
                        yield path
                    else:
                        limitations.append('Archivo especial omitido')
        except OSError:
            limitations.append('Directorio no legible: ' + folder.relative_to(root).as_posix())


def remove_owned_tree(root):
    """Remove only a previously checked, private staging/owned directory."""
    root = no_links(root)
    if not root.is_dir():
        raise ValueError('Directorio de limpieza inválido')
    paths = []
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(folder) / name
            no_links(p)
            if not p.resolve().is_relative_to(root.resolve()):
                raise ValueError('Limpieza fuera del destino')
            paths.append(p)
    for path in sorted(paths, key=lambda p: len(p.parts), reverse=True):
        if path.is_dir(): path.rmdir()
        else: path.unlink()
    root.rmdir()


def extract_zip(archive, destination, max_total_bytes=50_000_000, max_files=1000,
                max_file_bytes=2_000_000, max_ratio=100):
    destination = no_links(destination)
    archive = no_links(archive)
    if os.path.lexists(destination):
        raise ValueError('Destino existente; no se sobrescribe')
    if archive.stat().st_size > max_total_bytes:
        raise ValueError('ZIP demasiado grande')
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        if len(infos) > max_files: raise ValueError('Demasiadas entradas ZIP')
        total = 0; seen = set(); members = []
        for info in infos:
            # ZipInfo normalizes backslashes on Windows and truncates at NUL.
            # Validate the original central-directory name before that normalization.
            original = info.orig_filename
            relative_name(original[:-1] if original.endswith('/') else original)
            if original != info.filename:
                raise ValueError('Nombre ZIP alterado por normalización')
            name = info.filename[:-1] if info.is_dir() else info.filename
            rel = relative_name(name)
            key = name.casefold()
            if key in seen: raise ValueError('Entradas ZIP duplicadas')
            seen.add(key)
            mode = info.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError('Entrada ZIP no regular')
            if info.flag_bits & 1: raise ValueError('ZIP cifrado no admitido')
            total += info.file_size
            if total > max_total_bytes or info.file_size > max_file_bytes or \
               info.file_size > max(1, info.compress_size) * max_ratio:
                raise ValueError('Límite de tamaño/compresión ZIP excedido')
            members.append((info, rel))
        # Reject file/directory conflicts before publishing anything.
        files = {rel.as_posix().casefold() for info, rel in members if not info.is_dir()}
        for _, rel in members:
            if any(p.as_posix().casefold() in files for p in rel.parents if p != Path('.')):
                raise ValueError('Conflicto archivo/directorio ZIP')
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix='.saa-zip-', dir=destination.parent))
        try:
            actual_total = 0
            for info, rel in members:
                target = staging / rel
                if info.is_dir(): target.mkdir(parents=True, exist_ok=True); continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with z.open(info) as src, target.open('xb') as dst:
                    while chunk := src.read(65536):
                        written += len(chunk); actual_total += len(chunk)
                        if written > max_file_bytes or actual_total > max_total_bytes:
                            raise ValueError('Datos ZIP exceden límites')
                        dst.write(chunk)
            if os.path.lexists(destination): raise ValueError('Destino creado durante extracción')
            staging.rename(destination)
        finally:
            if staging.exists(): remove_owned_tree(staging)
    return destination
