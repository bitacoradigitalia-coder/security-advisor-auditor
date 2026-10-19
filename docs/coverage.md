# Cobertura y límites v2.1

## Lenguajes

Python 3.10+: AST de biblioteca estándar. Verificado aquí con Python 3.12 en Windows.
JS/TS/JSX/TSX/HTML/Astro: señales HTML heredadas, sin parser/taint; no se afirma
compatibilidad contextual. Otros lenguajes: inventario y secretos. No hay envío IA.

## Categorías y controles verificados

| Categoría | Modelo real | Controles reconocidos | Límites |
| --- | --- | --- | --- |
| Code injection | eval/exec y fuentes | eval de expresión literal aritmética; allowlist finita dominante | Código dinámico y reflexión sin resolver |
| SQL injection | execute/executemany, concatenación/f-string | texto fijo/parámetros; identificadores permitidos; conversión numérica | Formas de llamadas DB-API, no prueba de driver/ORM real |
| Command injection | os.system/popen y subprocess shell=True | comandos fijos o allowlist sin metacaracteres | Shell dinámico y programas indirectos pendientes |
| Argument injection | argumentos externos a curl/wget/ssh/tar/git | argv fijo | Opción/programa/versión/alcance requieren revisión |
| Path traversal | open/io.open y métodos Path | ruta fija; resolve + is_relative_to contra base fija con rechazo dominante | Enlaces, carreras y políticas runtime pendientes |
| SSRF | llamadas requests/httpx | URL fija invalida solo control directo del argumento | DNS/redirecciones/allowlist de redes sin modelar |
| Template injection | jinja2.Template/render_template_string | plantilla fija | Autoescape y plantillas externas pendientes |
| XSS | markupsafe.Markup | markupsafe.escape para texto HTML | Atributos/JS/URL y DOM JS no cubiertos por AST |
| Propiedad/tenant | formas Record.query.get/filter_by/first/all en rutas Flask | filtro owner/user/tenant contra current_user; guard de desigualdad + abort | No demuestra políticas de ORM, RLS ni despliegue |
| Firma JWT | jwt.decode options literal verify_signature=False | conserva hipótesis; no declara fallo de login | Uso de claims, algoritmos, claves, issuer/audience pendientes |
| Pickle/TLS | reglas anteriores conservadas | candidatos separados | Sin promesa de análisis completo |

Fuentes: input(), sys.argv/stdin, os.environ y flask.request args/form/json/headers/
cookies/data/files/get_json; parámetros de ruta. Archivos externos y bibliotecas
indirectas no identificables conservan incertidumbre, no se inventa control atacante.

## Frameworks

Flask/Blueprint (familias 2/3, formas route/get/post/put/patch/delete) y Flask-Login
(formas login_required/current_user). Se analiza la estructura sin instalar/importar
frameworks y sin certificar versión efectiva. login_required es señal de autenticación,
no prueba de autorización. Decoradores no reconocidos o before_request conocido
producen NOT_VERIFIED para la hipótesis de permiso no resuelta. Filtros de consulta
son evidencia local, no prueba del modelo de datos o de toda la política de acceso.

Referencias verificadas el 2026-10-11:
[Flask decorators](https://flask.palletsprojects.com/en/stable/patterns/viewdecorators/),
[Flask lifecycle](https://flask.palletsprojects.com/en/stable/lifecycle/),
[Flask-Login](https://flask-login.readthedocs.io/en/latest/),
[PyJWT](https://pyjwt.readthedocs.io/en/latest/usage.html).

## Cobertura incompleta y posibles errores

DEEP: solo funciones de mismo archivo, llamadas directas posicionales, sin
decoradores/variádicos y profundidad 4 por defecto. No resuelve todo un call graph.
Métodos, herencia, reflexión, funciones anidadas e indirectas conservan triaje
legacy cuando existe una regla. Llamadas entre archivos no correlacionadas.
Loops/try/with no tienen modelo completo: se investigan sinks y se invalidan
conclusiones de seguridad; se declara limitación. No modela todos los aliases,
mutaciones de contenedores, comprehensions, closures, import dinámico o concurrencia.

Falsos positivos posibles: execute que no es SQL; middleware/RLS externo que
protege un recurso; URL externa autorizada; opciones de programa restringidas fuera
de función; validación equivalente no reconocida. NOT_VERIFIED evita afirmación
categórica cuando hay indicios de control externo conocido, pero no elimina todas
las hipótesis innecesarias. Se mantienen motivos y precondiciones.

Falsos negativos posibles: SQL/ORM con API distinta, SSRF con cliente creado como
objeto, entrada indirecta de archivos/colas, decorators dinámicos, import/rebinding
complejo, sanitización/flujo entre archivos y scope fuera del modelo. No se detecta
BFLA o sesiones completas automáticamente. Escalada vertical, revocación/session
rotation, frontend-only auth, lectura/escritura asimétrica y roles globales requieren
revisión del agente con la metodología original. No marcar estas fases revisadas
por aprobar pruebas. No afirmar soporte avanzado exhaustivo de auth/authz.

Linux/macOS: código POSIX preparado, ejecución nativa no realizada. Activación real
de los cinco agentes pendiente; archivos de instalación sí verificados en destinos
sintéticos. Scanners opcionales siguen siendo descubrimiento/planes sin ejecución.

## Próximo v2.2

Corpus independiente y proyectos reales autorizados; parser JS/TS mantenible;
call graph entre módulos, CFG completo, modelos de ORM/RLS y roles/sesiones;
pruebas nativas POSIX y revisión externa de métricas. Sin cambiar la metodología.
