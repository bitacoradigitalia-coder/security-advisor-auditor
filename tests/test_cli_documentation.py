"""Check user-facing examples without executing scans or accessing the network."""
import argparse
import contextlib
import io
from pathlib import Path
import re
import shlex
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import audit


class ParserCaptured(Exception):
    pass


class CLIDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def capture(parser, *args, **kwargs):
            cls.parser = parser
            raise ParserCaptured
        with patch.object(argparse.ArgumentParser, 'parse_args', capture):
            try:
                audit.main([])
            except ParserCaptured:
                pass

        def disable_abbreviations(parser):
            parser.allow_abbrev = False
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    for child in action.choices.values():
                        disable_abbreviations(child)
        disable_abbreviations(cls.parser)

    def test_documented_audit_commands_parse(self):
        count = 0
        for relative in ('README.md', 'docs/usage.md'):
            content = (ROOT / relative).read_text(encoding='utf-8').replace('\\\n', ' ')
            for block in re.findall(r'```bash\n(.*?)```', content, re.S):
                for line in block.splitlines():
                    if not line.startswith('python scripts/audit.py '):
                        continue
                    args = shlex.split(line)[2:]
                    count += 1
                    with self.subTest(file=relative, command=line), \
                            contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(io.StringIO()):
                        try:
                            self.parser.parse_args(args)
                        except SystemExit as exc:
                            self.assertEqual(exc.code, 0)
        self.assertGreater(count, 20)

    def test_local_links_in_updated_guides_exist(self):
        for relative in ('README.md', 'docs/README.md', 'docs/usage.md',
                         'docs/cli.md', 'docs/roadmap.md'):
            path = ROOT / relative
            for target in re.findall(r'\]\(([^)]+)\)', path.read_text(encoding='utf-8')):
                if target.startswith(('https://', 'http://', '#', 'mailto:')):
                    continue
                target = target.split('#', 1)[0]
                with self.subTest(file=relative, link=target):
                    self.assertTrue((path.parent / target).exists())


if __name__ == '__main__':
    unittest.main()
