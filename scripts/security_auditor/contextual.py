"""Conservative AST/data-flow analysis. Target code is never imported or run."""
import ast
import time

from .authorization import denied, dotted, owner_guard, query_call, query_scope, route_model
from .dataflow import Value, merge, join_environments
from .verification import enrich_candidate, transition

RULES = {
    'code-injection': ('Evaluación dinámica contextual', 'CWE-95', 8, 'Sustituir evaluación por operaciones explícitas'),
    'sql-injection': ('Consulta SQL contextual', 'CWE-89', 8, 'Usar parámetros y listas permitidas para identificadores'),
    'command-injection': ('Comando interpretado por shell', 'CWE-78', 8, 'Usar argumentos separados sin shell y validar valores'),
    'argument-injection': ('Argumento externo para programa sensible', 'CWE-88', 8, 'Restringir opciones/destinos según el programa invocado'),
    'path-traversal': ('Acceso contextual a archivo', 'CWE-22', 13, 'Resolver y confinar rutas; revisar enlaces y carreras de archivos'),
    'ssrf': ('Destino HTTP contextual', 'CWE-918', 11, 'Restringir destinos, redirecciones y resolución DNS'),
    'template-injection': ('Plantilla dinámica contextual', 'CWE-1336', 8, 'Usar plantillas fijas con datos separados'),
    'xss': ('HTML marcado como seguro', 'CWE-79', 16, 'Escapar texto en su contexto, no marcar entrada externa como HTML seguro'),
    'resource-authorization': ('Ámbito del recurso solicitado', 'CWE-639', 4, 'Aplicar política de propiedad/tenant en el servidor'),
}
SHELL_CALLS = {'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_call', 'subprocess.check_output'}


def safe_expression(text):
    if not isinstance(text, str) or len(text) > 1000: return False
    try:
        tree = ast.parse(text, mode='eval')
        return all(isinstance(n, (ast.Expression, ast.Constant, ast.BinOp, ast.UnaryOp,
                                 ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
                                 ast.Mod, ast.UAdd, ast.USub, ast.Load)) for n in ast.walk(tree))
    except (ValueError, SyntaxError, RecursionError): return False


class Analyzer:
    def __init__(self, tree, name, limitations, mode, max_call_depth, deadline):
        self.tree = tree; self.name = name; self.limitations = limitations; self.mode = mode
        self.max_call_depth = max_call_depth; self.deadline = deadline
        self.aliases = {}; self.receivers = set(); self.findings = []; self.function = None
        self.model = {}; self.env = {}; self.call_stack = []; self.called = set()
        self.functions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.external_policy = False; self.emitted = {}
        self.globals = {}; self.opaque_flow = False
        self.visited_calls = set()
        for n in tree.body:
            if isinstance(n, ast.Import):
                for a in n.names: self.aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
            elif isinstance(n, ast.ImportFrom):
                for a in n.names: self.aliases[a.asname or a.name] = (n.module or '') + '.' + a.name
        for n in tree.body:
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and self.resolve(n.value.func) in ('flask.Flask', 'flask.Blueprint'):
                self.receivers.update(t.id for t in n.targets if isinstance(t, ast.Name))
        self.external_policy = any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
            any(dotted(d).endswith(('.before_request', '.before_app_request')) for d in n.decorator_list) for n in tree.body)

    def resolve(self, node):
        if isinstance(node, ast.Name):
            if node.id in self.env: return ''  # rebinding/shadowing is not an import alias
            if node.id in self.functions: return 'local:' + node.id
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute): return self.resolve(node.value) + '.' + node.attr
        return ''

    def check_time(self):
        if time.perf_counter() > self.deadline: raise TimeoutError()

    def source(self, node):
        name = self.resolve(node)
        if name.startswith(('flask.request.args', 'flask.request.form', 'flask.request.json',
                            'flask.request.headers', 'flask.request.cookies', 'flask.request.data',
                            'flask.request.files', 'sys.argv', 'sys.stdin', 'os.environ')):
            return Value((name,), (name,), False)
        return None

    def value(self, node):
        self.check_time()
        if node is None: return Value(unknown=True)
        src = self.source(node)
        if src: return src
        if isinstance(node, ast.Constant): return Value(literals=(node.value,), trace=('literal',))
        if isinstance(node, ast.Name): return self.env.get(node.id, Value(unknown=True, trace=(node.id,)))
        if isinstance(node, ast.Subscript): return self.value(node.value).step('subscript')
        if isinstance(node, ast.Attribute): return self.value(node.value).step('.' + node.attr)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            vals = [self.value(x) for x in node.elts]
            if all(v.literals and not v.sources and not v.unknown for v in vals):
                return Value(literals=(tuple(v.literals[0] for v in vals),), trace=('literal sequence',))
            return merge(*vals)
        if isinstance(node, ast.JoinedStr):
            vals = [self.value(n.value) if isinstance(n, ast.FormattedValue) else self.value(n) for n in node.values]
            dynamic = [v for v in vals if v.sources or v.unknown]
            return merge(*(dynamic or vals)).step('formatted-string')
        if isinstance(node, ast.BinOp):
            a, b = self.value(node.left), self.value(node.right)
            if isinstance(node.op, ast.Div) and a.resolved and not a.sources:
                return Value(b.sources, a.trace + b.trace + ('path join',), b.unknown, (), b.controls, False, dotted(node.left))
            if isinstance(node.op, ast.Add) and a.literals and b.literals and isinstance(a.literals[0], str) and isinstance(b.literals[0], str):
                return Value(literals=((a.literals[0] + b.literals[0])[:2000],), trace=('literal concatenation',))
            # Known constant pieces preserve controls on the dynamic part; joining two flows intersects them.
            if not a.sources and not a.unknown: return b.step('binary-operation')
            if not b.sources and not b.unknown: return a.step('binary-operation')
            return merge(a, b).step('binary-operation')
        if isinstance(node, ast.Call): return self.call(node)
        # Unsupported operations retain potential taint, never sanitize by name.
        return merge(*(self.value(n) for n in ast.iter_child_nodes(node) if isinstance(n, ast.expr))).step('unsupported-expression')

    def finding(self, node, category, value, mitigation=None, unresolved=None, context=None):
        from .engine import candidate
        title, cwe, phase, recommendation = RULES[category]
        finding = enrich_candidate(candidate(self.name, node.lineno, title, cwe, phase,
            'Observación contextual; alcanzabilidad y controles externos requieren revisión', recommendation), category, 'python-context-v2.1')
        finding['location'].update(function=self.function.name if self.function else None,
                                   line_end=getattr(node, 'end_lineno', node.lineno))
        sink = self.resolve(node.func) or dotted(node.func)
        finding['evidence'].update(kind='static_data_flow', source=list(value.sources), sink=sink,
            trace=list(value.trace) + [sink + '(...)'], controls=sorted(value.controls),
            mitigation=mitigation, context=context, snippet=sink + '(...)',
            summary=' → '.join(list(value.trace)[-8:] + [sink + '(...)']))
        finding['verification'].update(method='static-data-flow', limitations=[
            'Comportamiento en ejecución no probado', 'Alcanzabilidad y configuración externa pendientes'],
            result='source-to-sink-path-observed' if value.sources else 'context-observed')
        if self.mode == 'QUICK': pass
        elif unresolved:
            finding['verification']['limitations'].append(unresolved)
            transition(finding, 'NOT_VERIFIED', unresolved)
        elif mitigation and not self.opaque_flow:
            transition(finding, 'FALSE_POSITIVE', mitigation)
        elif value.sources or context:
            transition(finding, 'PROBABLE', 'Flujo o condición contextual observado; sin explotación ejecutada')
        else:
            finding['verification']['limitations'].append('Origen de datos o punto de entrada no resuelto')
            transition(finding, 'NOT_VERIFIED', 'Origen de datos o punto de entrada no resuelto')
        key = (node.lineno, category, self.function.name if self.function else '')
        prior = self.emitted.get(key)
        if prior:
            # A unsafe reachable call must not disappear behind a safe invocation of the same helper.
            rank = {'PROBABLE': 4, 'NOT_VERIFIED': 3, 'CANDIDATE': 2, 'FALSE_POSITIVE': 1}
            if rank[finding['status']] > rank[prior['status']]: prior.clear(); prior.update(finding)
            return prior
        self.findings.append(finding); self.emitted[key] = finding
        return finding

    def call(self, node):
        self.visited_calls.add(node.lineno)
        func = self.resolve(node.func)
        # Values are computed once: nested calls can emit evidence, never run code.
        args = [self.value(n) for n in node.args]
        kw = {k.arg: self.value(k.value) for k in node.keywords}
        value = args[0] if args else Value(unknown=True)
        if func in ('input', 'builtins.input', 'sys.stdin.read', 'sys.stdin.readline', 'flask.request.get_json'):
            return Value((func,), (func + '(...)',))
        if isinstance(node.func, ast.Attribute) and self.source(node.func.value):
            return self.source(node.func.value).step('.' + node.func.attr + '(...)')
        category = None; mitigation = None
        if func in ('eval', 'exec', 'builtins.eval', 'builtins.exec'):
            category = 'code-injection'
            if func.endswith('eval') and value.literals and all(safe_expression(x) for x in value.literals):
                mitigation = 'Expresión literal limitada a constantes y operaciones aritméticas'
            elif 'code-allowlist' in value.controls: mitigation = 'Lista finita de expresiones aritméticas con rechazo dominante'
        elif func in SHELL_CALLS:
            shell = kw.get('shell', Value(literals=(False,)))
            if shell.literals == (True,):
                category = 'command-injection'
                if 'command-allowlist' in value.controls: mitigation = 'Lista permitida de comandos literales sin metacaracteres'
                elif value.literals: mitigation = 'Comando literal: sin flujo externo observado en este argumento'
            elif shell.literals == (False,):
                if value.literals: category = 'command-injection'; mitigation = 'Argumentos fijos sin interpretación shell'
                elif isinstance(node.args[0] if node.args else None, (ast.List, ast.Tuple)):
                    elements = node.args[0].elts
                    executable = elements[0].value if elements and isinstance(elements[0], ast.Constant) else None
                    if executable in ('curl', 'wget', 'ssh', 'tar', 'git'):
                        category = 'argument-injection'; value = merge(*args)
                else:
                    self.limitations.append('Argumentos/proceso no resueltos: ' + self.name + ':' + str(node.lineno))
            else:
                category = 'command-injection'
        elif func in ('os.system', 'os.popen'):
            category = 'command-injection'
            if value.literals: mitigation = 'Comando fijo: hipótesis de flujo externo invalidada localmente'
            elif 'command-allowlist' in value.controls: mitigation = 'Comando restringido a lista finita'
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ('execute', 'executemany'):
            category = 'sql-injection'
            if value.literals: mitigation = 'Texto SQL fijo; valores separados en parámetros si existen'
            elif 'sql-allowlist' in value.controls: mitigation = 'Fragmento SQL restringido a identificadores literales'
            elif 'numeric-conversion' in value.controls: mitigation = 'Conversión numérica antes de interpolación SQL; sin fragmento de texto externo'
        elif func in ('open', 'builtins.open', 'io.open') or isinstance(node.func, ast.Attribute) and node.func.attr in ('read_text', 'read_bytes', 'write_text', 'write_bytes', 'open'):
            category = 'path-traversal'
            if isinstance(node.func, ast.Attribute) and func not in ('io.open', 'builtins.open'): value = self.value(node.func.value)
            if value.literals: mitigation = 'Nombre de archivo fijo: sin traversal controlado observado'
            elif 'path-confinement' in value.controls: mitigation = 'Ruta resuelta con confinamiento estructural; enlaces y carreras runtime pendientes'
        elif func.startswith(('requests.', 'httpx.')) and func.rsplit('.', 1)[-1] in ('get', 'post', 'put', 'patch', 'delete', 'head', 'request'):
            category = 'ssrf'
            if func.endswith('.request'): value = args[1] if len(args) > 1 else kw.get('url', Value(unknown=True))
            elif not args: value = kw.get('url', Value(unknown=True))
            if value.literals: mitigation = 'URL fija: sin destino directamente controlado en esta llamada'
        elif func in ('jinja2.Template', 'flask.render_template_string'):
            category = 'template-injection'
            if value.literals: mitigation = 'Texto de plantilla fijo; datos separados'
        elif func == 'markupsafe.Markup':
            category = 'xss'
            if 'html-text-escape' in value.controls: mitigation = 'Escape MarkupSafe aplicado al texto HTML'
            elif value.literals: mitigation = 'HTML fijo sin entrada externa observada'
        if category == 'ssrf' and not value.sources and not value.literals:
            self.limitations.append('Destino HTTP no resuelto: ' + self.name + ':' + str(node.lineno)); category = None
        if category and (self.mode != 'QUICK' or category == 'code-injection' or
                category == 'command-injection' and (func in ('os.system', 'os.popen') or kw.get('shell', Value()).literals == (True,))):
            self.finding(node, category, value, mitigation=mitigation)
        if self.mode != 'QUICK' and self.model.get('route') and query_call(node):
            scope = query_scope(node, self.aliases)
            control_unknown = self.model.get('unresolved') or self.external_policy
            self.finding(node, 'resource-authorization', merge(*args, *kw.values()),
                mitigation=scope, unresolved='Decorador/middleware externo o política no resuelta' if control_unknown and not scope else None,
                context={'authentication': self.model.get('authentication', False),
                         'action': dotted(node.func).rsplit('.', 1)[-1], 'policy': scope or 'no observada en la función'})
        # Preserve v2.0.1 rules not replaced by the new contextual categories.
        if func in ('pickle.load', 'pickle.loads') or func.startswith(('requests.', 'httpx.')) and kw.get('verify', Value()).literals == (False,):
            from .engine import candidate
            cwe = 'CWE-502' if func.startswith('pickle.') else 'CWE-295'
            f = enrich_candidate(candidate(self.name, node.lineno, 'Deserialización pickle' if cwe == 'CWE-502' else 'Verificación TLS desactivada',
                cwe, 8 if cwe == 'CWE-502' else 14, 'Condición sensible; contexto de despliegue pendiente',
                'Usar datos sin ejecución' if cwe == 'CWE-502' else 'Activar validación TLS'), cwe)
            f['location']['function'] = self.function.name if self.function else None
            self.findings.append(f)
        if func in ('int', 'float', 'builtins.int', 'builtins.float'):
            return value.control('numeric-conversion')
        if func in ('str', 'builtins.str'): return value.step('str(...)')
        if func == 'markupsafe.escape': return value.control('html-text-escape')
        if func in ('pathlib.Path', 'Path'):
            return value.step('Path(...)')
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'resolve':
            p = self.value(node.func.value)
            return Value(p.sources, p.trace + ('resolve()',), p.unknown, p.literals, p.controls, True, p.base)
        if func.startswith('local:'):
            function = self.functions[func[6:]]
            if self.mode == 'DEEP' and not function.decorator_list and not function.args.vararg and not function.args.kwarg and not function.args.kwonlyargs:
                params = function.args.posonlyargs + function.args.args
                if len(args) == len(params) and not kw and len(self.call_stack) < self.max_call_depth and function.name not in self.call_stack:
                    self.called.add(function.name)
                    return self.run_function(function, dict(zip((p.arg for p in params), args)), {})
            self.limitations.append('Llamada local no correlacionada: ' + self.name + ':' + str(node.lineno))
        if isinstance(node.func, ast.Attribute):
            base = self.value(node.func.value)
            v = merge(base, *args, *kw.values()).step('.' + node.func.attr + '(...)')
            return Value(v.sources, v.trace, True)
        # Unknown transformations preserve taint but are not accepted as sanitizers.
        if args:
            v = merge(*args, *kw.values()).step((func or 'indirect-call') + '(...)')
            return Value(v.sources, v.trace, True)
        return Value(unknown=True, trace=((func or 'indirect-call') + '(...)',))

    def refine(self, test, env, truth=True):
        """Refine only a matching, dominating true branch; never infer by function name."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.refine(test.operand, env, not truth)
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name):
            if (isinstance(test.ops[0], ast.In) and truth) or (isinstance(test.ops[0], ast.NotIn) and not truth):
                collection = test.comparators[0]
                if isinstance(collection, (ast.List, ast.Tuple, ast.Set)) and 0 < len(collection.elts) <= 100 and all(isinstance(x, ast.Constant) and isinstance(x.value, (str, int, float)) for x in collection.elts):
                    values = [x.value for x in collection.elts]; v = env.get(test.left.id, Value(unknown=True))
                    if all(safe_expression(x) for x in values): v = v.control('code-allowlist')
                    if all(isinstance(x, str) and x.replace('_', '').isalnum() for x in values): v = v.control('sql-allowlist')
                    if all(isinstance(x, str) and x.replace('_', '').replace('-', '').isalnum() for x in values): v = v.control('command-allowlist')
                    env[test.left.id] = v
        if truth and isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.func.attr == 'is_relative_to' and isinstance(test.func.value, ast.Name) and len(test.args) == 1 and isinstance(test.args[0], ast.Name):
            p = env.get(test.func.value.id, Value()); base = env.get(test.args[0].id, Value(unknown=True))
            if p.resolved and base.resolved and not base.sources and not base.unknown and p.base == test.args[0].id:
                env[test.func.value.id] = p.control('path-confinement')

    def block(self, body):
        returns = []
        resource_assignments = {}
        for index, n in enumerate(body):
            self.check_time()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): continue
            if isinstance(n, (ast.Import, ast.ImportFrom)): continue
            if isinstance(n, ast.Assign):
                v = self.value(n.value)
                for target in n.targets:
                    if isinstance(target, ast.Name):
                        self.env[target.id] = v.step(target.id)
                        resource_assignments.pop(target.id, None)
                        if isinstance(n.value, ast.Call) and query_call(n.value):
                            resource_assignments[target.id] = (index, self.emitted.get((n.value.lineno, 'resource-authorization', self.function.name if self.function else '')))
            elif isinstance(n, ast.AnnAssign):
                v = self.value(n.value)
                if isinstance(n.target, ast.Name): self.env[n.target.id] = v.step(n.target.id)
            elif isinstance(n, ast.AugAssign):
                if isinstance(n.target, ast.Name): self.env[n.target.id] = merge(self.env.get(n.target.id, Value(unknown=True)), self.value(n.value)).step(n.target.id)
            elif isinstance(n, ast.If):
                self.value(n.test)
                original = dict(self.env); then = dict(original); other = dict(original)
                self.refine(n.test, then, True); self.refine(n.test, other, False)
                self.env = then; self.block(n.body); then = self.env
                self.env = other; self.block(n.orelse); other = self.env
                stop_then = denied(n.body, self.aliases) or any(isinstance(x, ast.Return) for x in n.body)
                stop_other = denied(n.orelse, self.aliases) or any(isinstance(x, ast.Return) for x in n.orelse)
                self.env = other if stop_then and not stop_other else then if stop_other and not stop_then else join_environments(then, other)
                owner = owner_guard(n.test, self.aliases)
                resource = resource_assignments.get(owner)
                f = resource[1] if resource and resource[0] == index - 1 else None
                if f and denied(n.body, self.aliases) and f['status'] == 'PROBABLE' and not self.model.get('unresolved') and not self.external_policy:
                    f['evidence']['mitigation'] = 'Rechazo dominante si propietario/tenant difiere de la identidad Flask-Login'
                    transition(f, 'FALSE_POSITIVE', f['evidence']['mitigation'])
            elif isinstance(n, ast.Return):
                returns.append(self.value(n.value)); break
            elif isinstance(n, ast.Raise):
                if n.exc: self.value(n.exc)
                break
            elif isinstance(n, ast.Expr): self.value(n.value)
            else:
                # Loops/try/with have complex paths: process possible sinks, invalidate refinements.
                self.limitations.append('Control de flujo complejo no resuelto: ' + self.name + ':' + str(getattr(n, 'lineno', 1)))
                original = dict(self.env)
                previous_opaque = self.opaque_flow; self.opaque_flow = True
                for child in ast.iter_child_nodes(n):
                    if isinstance(child, ast.expr): self.value(child)
                for field in ('body', 'orelse', 'finalbody'):
                    children = getattr(n, field, None)
                    if children:
                        self.env = dict(original); self.block(children)
                for handler in getattr(n, 'handlers', []):
                    self.env = dict(original); self.block(handler.body)
                self.env = join_environments(original, self.env)
                self.opaque_flow = previous_opaque
        return merge(*returns) if returns else Value(unknown=True)

    def run_function(self, function, env, model):
        previous = (self.function, self.env, self.model)
        # Global reads are modeled from module assignments, but local names hide globals
        # even before their first assignment (Python lexical scope).
        local_names = {n.id for n in ast.walk(function) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        inherited = {k: v for k, v in self.globals.items() if k not in local_names}
        self.function, self.env, self.model = function, {**inherited, **env}, model
        self.call_stack.append(function.name)
        try: return self.block(function.body)
        finally:
            self.call_stack.pop(); self.function, self.env, self.model = previous

    def run(self):
        self.block(self.tree.body)
        self.globals = dict(self.env)
        for function in self.functions.values():
            if function.name in self.called: continue
            model = route_model(function, self.aliases, self.receivers)
            env = {p.arg: Value(('route-parameter:' + p.arg,), (p.arg,)) if model['route'] else Value(unknown=True, trace=(p.arg,)) for p in function.args.posonlyargs + function.args.args + function.args.kwonlyargs}
            self.run_function(function, env, model)
        return self.findings


def analyze_python(text, name, limitations, mode='STANDARD', max_nodes=50000,
                   max_memory_bytes=128_000_000, max_call_depth=4, deadline=None):
    if mode not in ('QUICK', 'STANDARD', 'DEEP'): raise ValueError('Modo inválido')
    if min(max_nodes, max_memory_bytes, max_call_depth) <= 0: raise ValueError('Límites AST inválidos')
    # Conservative allocation estimate, NOT an OS/RSS hard cap. Documented explicitly.
    if len(text.encode('utf-8')) * 64 > max_memory_bytes:
        limitations.append('Presupuesto estimado de memoria alcanzado: ' + name); return []
    deadline = deadline if deadline is not None else time.perf_counter() + 30
    try:
        tree = ast.parse(text, filename='<untrusted>')
        count = 0
        for node in ast.walk(tree):
            count += 1
            if count > max_nodes or count * 1024 > max_memory_bytes:
                limitations.append('Límite de nodos/memoria AST alcanzado: ' + name); return []
            if time.perf_counter() > deadline: raise TimeoutError()
        analyzer = Analyzer(tree, name, limitations, mode, max_call_depth, deadline)
        results = analyzer.run()
        # Preserve previous syntactic coverage for class/nested/unreachable scopes,
        # without presenting it as a resolved data-flow path.
        from .engine import python_candidates
        for f in python_candidates(text, name, []):
            if f['location']['line_start'] not in analyzer.visited_calls:
                enrich_candidate(f)
                if mode != 'QUICK':
                    f['verification']['limitations'].append('Método, función anidada o flujo no resuelto')
                    transition(f, 'NOT_VERIFIED', 'Scope o alcanzabilidad fuera del modelo contextual')
                results.append(f)
        return results
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        limitations.append('AST no disponible/sintaxis o complejidad no admitida: ' + name); return []
    except TimeoutError:
        limitations.append('Límite de tiempo de análisis alcanzado: ' + name); return []
