"""
Laboratorio vulnerable AUTORIZADO (mejora 3).

Mini aplicacion web deliberadamente insegura, construida SOLO con la
libreria estandar (http.server), que se levanta en 127.0.0.1 en un puerto
efimero dentro de los tests de integracion. Permite ejercitar el
ActiveScanner contra un objetivo real sin tocar ningun sistema externo.

Vulnerabilidades intencionales:
- Cabeceras de seguridad ausentes en todas las respuestas.
- Cookie de sesion sensible sin HttpOnly ni Secure.
- Endpoint /debug que expone informacion de depuracion (debug=true),
  revelado por robots.txt (information disclosure).
- /robots.txt que revela rutas privadas (/private/).
"""

import http.server
import threading

HOME_HTML = """<!DOCTYPE html>
<html><head><title>Laboratorio Vulnerable</title></head>
<body><h1>Laboratorio vulnerable autorizado</h1>
<p>App de pruebas para el ActiveScanner.</p></body></html>"""

DEBUG_BODY = "config: debug=true, display_errors=On, env=dev"

ROBOTS_BODY = (
    "User-agent: *" + chr(10)
    + "Disallow: /private/" + chr(10)
    + "Disallow: /debug" + chr(10)
)


class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    """Handler deliberadamente inseguro del laboratorio."""

    def log_message(self, format, *args):
        pass  # silenciar logs en los tests

    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        # VULNERABLE: cookie sensible sin HttpOnly ni Secure
        self.send_header("Set-Cookie", "session_id=abc123def456; Path=/")
        self.end_headers()
        self.wfile.write(data)

    def route(self, method):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, HOME_HTML)
        elif path == "/debug":
            self._send(200, DEBUG_BODY, "text/plain; charset=utf-8")
        elif path == "/robots.txt":
            self._send(200, ROBOTS_BODY, "text/plain; charset=utf-8")
        elif path == "/private/":
            self._send(200, "zona privada expuesta por robots.txt")
        else:
            self._send(404, "no encontrado")

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    def do_OPTIONS(self):
        self.route("OPTIONS")


class VulnerableApp:
    """Servidor del laboratorio: arranca en un hilo daemon y para limpio."""

    def __init__(self):
        self._server = None
        self._thread = None
        self.port = None

    def start(self) -> str:
        """Arranca el servidor en 127.0.0.1 en un puerto efimero y devuelve la URL base."""
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return "http://127.0.0.1:" + str(self.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None