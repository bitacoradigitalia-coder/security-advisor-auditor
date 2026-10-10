"""Source roots and GitHub-format archives: trusted installer, no archive code execution."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def copy_source(destination, newline='lf'):
    import install
    for name, data in install.payload().items():
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
        if name == 'references/audit-methodology.md':
            data = data.decode('utf-8-sig').replace('\r\n', '\n').encode('utf-8')
            if newline == 'crlf': data = data.replace(b'\n', b'\r\n')
        path.write_bytes(data)
    return destination


def archive_source(path, prefixes, replacements=None):
    import install
    contents = install.payload()
    contents.update(replacements or {})
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for prefix in prefixes:
            for name, data in contents.items():
                if name == 'references/audit-methodology.md': data = data.replace(b'\r\n', b'\n')
                archive.writestr(prefix + name, data)


class SourceTests(unittest.TestCase):
    def command(self, script, args, cwd):
        return subprocess.run([sys.executable, '-B', str(script), *map(str, args)], cwd=cwd,
                              capture_output=True, text=True, timeout=30)

    def test_install_renamed_sources_from_root_and_parent_all_profiles(self):
        for name in ['security-advisor-auditor', 'security-advisor-auditor-main',
                     'security-advisor-auditor-v2.0.0', 'custom-download']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                base = Path(td); source = copy_source(base / name)
                for agent in ['hermes', 'openclaw', 'opencode', 'codex', 'claude']:
                    skills = base / ('skills-' + agent)
                    cwd = source if agent in ('hermes', 'codex') else base
                    args = ['--agent', agent, '--skills-dir', skills]
                    r = self.command(source / 'install.py', args + ['--dry-run'], cwd)
                    self.assertEqual(r.returncode, 0, r.stderr); self.assertFalse(skills.exists())
                    r = self.command(source / 'install.py', args, cwd)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    dest = skills / 'security-advisor-auditor'
                    self.assertEqual((dest / 'references/audit-methodology.md').read_bytes(),
                                     (source / 'references/audit-methodology.md').read_bytes())
                    self.assertEqual((dest / 'adapters/profiles.json').read_bytes(), (ROOT / 'adapters/profiles.json').read_bytes())
                    self.assertNotEqual(self.command(source / 'install.py', args, cwd).returncode, 0)
                    r = self.command(source / 'install.py', args + ['--uninstall'], cwd)
                    self.assertEqual(r.returncode, 0, r.stderr); self.assertFalse(dest.exists())

    def test_validate_renamed_source_and_unique_parent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); source = copy_source(base / 'arbitrary-name')
            for location in (source, base):
                r = self.command(ROOT / 'scripts/audit.py', ['validate-skill', location], base)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_source_option_parent_and_ambiguous_roots(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); source = copy_source(base / 'one')
            skills = base / 'installed'
            args = ['--agent', 'hermes', '--source', base, '--skills-dir', skills, '--dry-run']
            r = self.command(ROOT / 'install.py', args, ROOT)
            self.assertEqual(r.returncode, 0, r.stderr); self.assertFalse(skills.exists())
            copy_source(base / 'two')
            r = self.command(ROOT / 'install.py', args, ROOT)
            self.assertEqual(r.returncode, 2)
            self.assertFalse(skills.exists())

    def test_github_format_zip_and_arbitrary_archive_names(self):
        for archive_name, prefix in [('security-advisor-auditor-main.zip', 'security-advisor-auditor-main/'),
                                     ('another-name.zip', 'download-v2/'), ('flat.zip', '')]:
            with self.subTest(archive=archive_name), tempfile.TemporaryDirectory() as td:
                base = Path(td); archive = base / archive_name
                archive_source(archive, [prefix])
                skills = base / 'skills'; args = ['--agent', 'opencode', '--source', archive, '--skills-dir', skills]
                r = self.command(ROOT / 'install.py', args + ['--dry-run'], ROOT)
                self.assertEqual(r.returncode, 0, r.stderr); self.assertFalse(skills.exists())
                r = self.command(ROOT / 'install.py', args, ROOT)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue((skills / 'security-advisor-auditor/SKILL.md').exists())
                r = self.command(ROOT / 'install.py', ['--agent', 'opencode', '--skills-dir', skills, '--uninstall'], ROOT)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_ambiguous_zip_rejected_before_install(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); archive = base / 'two.zip'; archive_source(archive, ['one/', 'two/'])
            r = self.command(ROOT / 'install.py', ['--agent', 'codex', '--source', archive, '--skills-dir', base / 'skills'], ROOT)
            self.assertEqual(r.returncode, 2); self.assertFalse((base / 'skills').exists())

    def test_malicious_zip_never_installs_or_executes(self):
        for path in ('../escape.py', '/absolute', 'C:/file', 'file:stream'):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as td:
                base = Path(td); archive = base / 'bad.zip'; archive_source(archive, ['repo/'])
                with zipfile.ZipFile(archive, 'a') as z: z.writestr(path, 'raise RuntimeError("never run")')
                r = self.command(ROOT / 'install.py', ['--agent', 'codex', '--source', archive, '--skills-dir', base / 'skills'], ROOT)
                self.assertEqual(r.returncode, 2); self.assertFalse((base / 'skills').exists())
                self.assertFalse((base / 'escape.py').exists())
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); archive = base / 'link.zip'; archive_source(archive, ['repo/'])
            with zipfile.ZipFile(archive, 'a') as z:
                info = zipfile.ZipInfo('repo/link'); info.create_system = 3; info.external_attr = 0o120777 << 16
                z.writestr(info, 'outside')
            r = self.command(ROOT / 'install.py', ['--agent', 'hermes', '--source', archive, '--skills-dir', base / 'skills'], ROOT)
            self.assertEqual(r.returncode, 2); self.assertFalse((base / 'skills').exists())

    def test_wrong_identity_and_incomplete_roots_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); source = copy_source(base / 'security-advisor-auditor')
            text = (source / 'SKILL.md').read_text(encoding='utf-8').replace('name: security-advisor-auditor', 'name: other-skill')
            (source / 'SKILL.md').write_text(text, encoding='utf-8')
            r = self.command(ROOT / 'install.py', ['--agent', 'codex', '--source', source, '--skills-dir', base / 'skills'], ROOT)
            self.assertEqual(r.returncode, 2); self.assertFalse((base / 'skills').exists())
            incomplete = base / 'incomplete'; incomplete.mkdir()
            (incomplete / 'SKILL.md').write_bytes((ROOT / 'SKILL.md').read_bytes())
            r = self.command(ROOT / 'install.py', ['--agent', 'codex', '--source', incomplete, '--skills-dir', base / 'skills'], ROOT)
            self.assertEqual(r.returncode, 2); self.assertFalse((base / 'skills').exists())

    def test_zip_code_is_copied_but_never_imported_or_executed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); archive = base / 'untrusted.zip'; marker = base / 'EXECUTED'
            code = ('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("ran")\n').encode('utf-8')
            archive_source(archive, ['repo-main/'], {'install.py': code, 'scripts/security_auditor/validation.py': code})
            r = self.command(ROOT / 'install.py', ['--agent', 'hermes', '--source', archive, '--skills-dir', base / 'skills'], ROOT)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual((base / 'skills/security-advisor-auditor/install.py').read_bytes(), code)

    def test_source_junction_is_rejected(self):
        import os
        if os.name != 'nt': self.skipTest('Windows junction test')
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); source = copy_source(base / 'repo-main'); outside = base / 'outside'; outside.mkdir()
            link = source / 'link'
            r = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(outside)], capture_output=True)
            if r.returncode: self.skipTest('Junction creation unavailable')
            try:
                r = self.command(ROOT / 'install.py', ['--agent', 'codex', '--source', source, '--skills-dir', base / 'skills'], ROOT)
                self.assertEqual(r.returncode, 2); self.assertFalse((base / 'skills').exists())
            finally: link.rmdir()

    def test_canonical_integrity_accepts_line_endings_rejects_content_change(self):
        from security_auditor.integrity import verify_methodology
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); path = base / 'method.md'
            original = (ROOT / 'references/audit-methodology.md').read_bytes().replace(b'\r\n', b'\n')
            for data in (original, original.replace(b'\n', b'\r\n'), b'\xef\xbb\xbf' + original):
                path.write_bytes(data)
                result = verify_methodology(path)
                self.assertEqual(result['canonical_sha256'], '904d385ea10a960b5b0b383b99471fc3250c0f753ef63a3d5a36f86ebeed928a')
            path.write_bytes(original.replace(b'Code is the source of truth', b'Code is never the source of truth'))
            with self.assertRaises(ValueError): verify_methodology(path)

    def test_changed_methodology_blocks_source_install_despite_21_phases(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); source = copy_source(base / 'repo-main')
            method = source / 'references/audit-methodology.md'
            method.write_bytes(method.read_bytes().replace(b'Never exaggerate severity.', b'Always exaggerate severity.'))
            r = self.command(ROOT / 'install.py', ['--agent', 'hermes', '--source', source, '--skills-dir', base / 'skills'], ROOT)
            self.assertEqual(r.returncode, 2); self.assertFalse((base / 'skills').exists())


if __name__ == '__main__': unittest.main()
