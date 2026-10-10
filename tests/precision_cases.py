"""Synthetic source text: parsed only, never imported or executed."""
FLASK = 'from flask import Flask, request, abort\nfrom flask_login import current_user, login_required\napp = Flask(__name__)\n'


def route(body, decorators=''):
    return FLASK + '@app.route("/resource/<resource_id>")\n' + decorators + 'def endpoint(resource_id):\n' + ''.join('    ' + line + '\n' for line in body.splitlines())


# Expectations are committed before implementation, not derived from its output.
CASES = [
    ('A1_constant_eval', 'context', 'code-injection', False, 'FALSE_POSITIVE', 'eval("2 + 2")'),
    ('A2_external_eval', 'context', 'code-injection', True, 'PROBABLE', 'x = input()\ny = x\neval(y)'),
    ('A3_unresolved_entry', 'context', 'code-injection', None, 'NOT_VERIFIED', 'def hidden(x):\n    return eval(x)'),
    ('A4_effective_validation', 'context', 'code-injection', False, 'FALSE_POSITIVE', 'x = input()\nif x not in ("2 + 2", "3 + 3"):\n    raise ValueError()\neval(x)'),
    ('A5_insufficient_validation', 'context', 'code-injection', True, 'PROBABLE', 'x = input()\nif len(x) > 100:\n    raise ValueError()\neval(x)'),
    ('B6_parameterized', 'sql', 'sql-injection', False, 'FALSE_POSITIVE', 'x = input()\ncursor.execute("SELECT * FROM users WHERE id = ?", (x,))'),
    ('B7_concatenated', 'sql', 'sql-injection', True, 'PROBABLE', 'x = input()\nq = "SELECT * FROM users WHERE id = " + x\ncursor.execute(q)'),
    ('B8_orm_parameters', 'sql', 'sql-injection', False, None, 'x = input()\nUser.query.filter_by(name=x).first()'),
    ('B9_identifier_allowlist', 'sql', 'sql-injection', False, 'FALSE_POSITIVE', 'table = input()\nif table not in ("users", "orders"):\n    raise ValueError()\ncursor.execute(f"SELECT * FROM {table}")'),
    ('B10_dynamic_fragment', 'sql', 'sql-injection', True, 'PROBABLE', 'q = input()\ncursor.execute(f"SELECT * FROM users ORDER BY {q}")'),
    ('C11_fixed_argv', 'command', 'command-injection', False, 'FALSE_POSITIVE', 'import subprocess\nsubprocess.run(["echo", "hello"])'),
    ('C12_external_shell', 'command', 'command-injection', True, 'PROBABLE', 'import subprocess\nx = input()\nsubprocess.run("echo " + x, shell=True)'),
    ('C13_program_arguments', 'command', 'argument-injection', True, 'PROBABLE', 'import subprocess\nx = input()\nsubprocess.run(["curl", x])'),
    ('C14_command_allowlist', 'command', 'command-injection', False, 'FALSE_POSITIVE', 'import subprocess\nx = input()\nif x not in ("date", "whoami"):\n    raise ValueError()\nsubprocess.run(x, shell=True)'),
    ('D15_fixed_file', 'path', 'path-traversal', False, 'FALSE_POSITIVE', 'open("fixed.txt")'),
    ('D16_external_path', 'path', 'path-traversal', True, 'PROBABLE', 'x = input()\np = "/uploads/" + x\nopen(p)'),
    ('D17_confined_path', 'path', 'path-traversal', False, 'FALSE_POSITIVE', 'from pathlib import Path\nbase = Path("/uploads").resolve()\np = (base / input()).resolve()\nif not p.is_relative_to(base):\n    raise ValueError()\nopen(p)'),
    ('D18_text_prefix', 'path', 'path-traversal', True, 'PROBABLE', 'from pathlib import Path\nbase = Path("/uploads").resolve()\np = (base / input()).resolve()\nif not str(p).startswith(str(base)):\n    raise ValueError()\nopen(p)'),
    ('E19_owner_query', 'authorization', 'resource-authorization', False, 'FALSE_POSITIVE', route('return Record.query.filter_by(id=resource_id, owner_id=current_user.id).first()', '@login_required\n')),
    ('E20_missing_owner', 'authorization', 'resource-authorization', True, 'PROBABLE', route('return Record.query.get(resource_id)')),
    ('E21_authenticated_tenant', 'authorization', 'resource-authorization', False, 'FALSE_POSITIVE', route('return Record.query.filter_by(id=resource_id, tenant_id=current_user.tenant_id).first()', '@login_required\n')),
    ('E22_client_tenant', 'authorization', 'resource-authorization', True, 'PROBABLE', route('return Record.query.filter_by(id=resource_id, tenant_id=request.args["tenant"]).first()')),
    ('E23_owner_guard', 'authorization', 'resource-authorization', False, 'FALSE_POSITIVE', route('obj = Record.query.get(resource_id)\nif obj.owner_id != current_user.id:\n    abort(403)\nreturn obj', '@login_required\n')),
    ('E24_authentication_only', 'authorization', 'resource-authorization', True, 'PROBABLE', route('return Record.query.get(resource_id)', '@login_required\n')),
    ('E25_external_middleware', 'authorization', 'resource-authorization', None, 'NOT_VERIFIED', route('return Record.query.get(resource_id)', '@external_access_policy\n')),
    ('S1_ssrf', 'ssrf', 'ssrf', True, 'PROBABLE', 'import requests\nx = input()\nrequests.get(x)'),
    ('S2_ssrf_constant', 'ssrf', 'ssrf', False, 'FALSE_POSITIVE', 'import requests\nrequests.get("https://example.invalid")'),
    ('T1_template', 'template', 'template-injection', True, 'PROBABLE', 'from jinja2 import Template\nTemplate(input()).render()'),
    ('X1_html', 'xss', 'xss', True, 'PROBABLE', 'from markupsafe import Markup\nMarkup(input())'),
    ('X2_context_escape', 'xss', 'xss', False, 'FALSE_POSITIVE', 'from markupsafe import Markup, escape\nMarkup(escape(input()))'),
]
