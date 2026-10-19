"""Bounded Flask routes and query-shape observations, not policy proofs."""
import ast


def dotted(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return dotted(node.value) + '.' + node.attr
    if isinstance(node, ast.Call): return dotted(node.func)
    return ''


def route_model(function, aliases, receivers):
    decorators = [dotted(d) for d in function.decorator_list]
    routes = [d for d in decorators if any(d == r + '.' + method for r in receivers
               for method in ('route', 'get', 'post', 'put', 'patch', 'delete'))]
    other = [d for d in decorators if d not in routes]
    known_auth = [d for d in other if aliases.get(d, d) == 'flask_login.login_required']
    return {'route': bool(routes), 'authentication': bool(known_auth),
            'unresolved': bool(set(other) - set(known_auth)), 'decorators': decorators}


def query_call(node):
    name = dotted(node.func)
    return '.query.' in name and name.rsplit('.', 1)[-1] in ('get', 'get_or_404', 'first', 'first_or_404', 'all')


def query_scope(node, aliases):
    """A filter_by keyword shape is evidence about this query, not the entire API."""
    for part in ast.walk(node):
        if isinstance(part, ast.Call) and dotted(part.func).endswith('.filter_by'):
            for k in part.keywords:
                if k.arg in ('owner_id', 'user_id', 'tenant_id'):
                    value = dotted(k.value)
                    identity, _, attribute = value.rpartition('.')
                    expected = 'tenant_id' if k.arg == 'tenant_id' else 'id'
                    if aliases.get(identity, identity) == 'flask_login.current_user' and attribute == expected:
                        return k.arg + ' ligado a flask_login.current_user'
    return None


def denied(body, aliases):
    """Only unconditional termination; unrelated nested branches do not count."""
    for node in body:
        if isinstance(node, ast.Raise): return True
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            name = dotted(node.value.func)
            if aliases.get(name, name) == 'flask.abort' and node.value.args and \
                    isinstance(node.value.args[0], ast.Constant) and node.value.args[0].value in (401, 403, 404):
                return True
    return False


def owner_guard(test, aliases):
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.NotEq):
        return None
    a, b = test.left, test.comparators[0]
    for resource, identity in ((a, b), (b, a)):
        if isinstance(resource, ast.Attribute) and isinstance(resource.value, ast.Name):
            value = dotted(identity); root, _, field = value.rpartition('.')
            if resource.attr in ('owner_id', 'user_id', 'tenant_id') and \
                    aliases.get(root, root) == 'flask_login.current_user' and \
                    field == ('tenant_id' if resource.attr == 'tenant_id' else 'id'):
                return resource.value.id
    return None
