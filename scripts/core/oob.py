"""
OOB interaction module for Security Advisor Auditor v2.3 (mejora M11).

Canal de retorno out-of-band (estilo interactsh) para confirmar
vulnerabilidades ciegas (blind SSRF, blind XXE, blind RCE). Cuando el
callback llega al servidor OOB, el hallazgo pasa de PROBABLE a CONFIRMED
con evidencia real de la interaccion.

OOBServer: servidor HTTP local (127.0.0.1, puerto efimero, stdlib sola)
para pruebas y auditorias autorizadas. La interfaz es agnostica: en
produccion puede sustituirse por un servidor remoto compatible a traves
de OOBClient sin cambiar el codigo que lo invoca.
"""

import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple, cast


@dataclass
class OOBCallback:
    """Un callback OOB recibido por el servidor de interaccion."""
    callback_id: str
    interaction_id: str
    timestamp: datetime
    remote_addr: str
    method: str
    path: str
    user_agent: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'callback_id': self.callback_id,
            'interaction_id': self.interaction_id,
            'timestamp': self.timestamp.isoformat(),
            'remote_addr': self.remote_addr,
            'method': self.method,
            'path': self.path,
            'user_agent': self.user_agent,
        }


class _OOBHTTPServer(ThreadingHTTPServer):
    """Servidor HTTP que registra cada peticion en el OOBServer propietario."""

    def __init__(self, address: Tuple[str, int], oob: "OOBServer") -> None:
        super().__init__(address, _CallbackHandler)
        self.oob = oob


class _CallbackHandler(BaseHTTPRequestHandler):
    """Handler que trata cada peticion como un callback OOB."""

    def _record(self, method: str) -> None:
        server = cast(_OOBHTTPServer, self.server)
        path = self.path or "/"
        interaction_id = path.lstrip("/").split("/")[0] or "root"
        callback = OOBCallback(
            callback_id=uuid.uuid4().hex[:16],
            interaction_id=interaction_id,
            timestamp=datetime.now(timezone.utc),
            remote_addr=str(self.client_address[0]),
            method=method,
            path=path,
            user_agent=self.headers.get("User-Agent", ""),
        )
        server.oob.record_callback(callback)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._record("GET")

    def do_POST(self) -> None:
        self._record("POST")

    def do_PUT(self) -> None:
        self._record("PUT")

    def do_DELETE(self) -> None:
        self._record("DELETE")

    def do_OPTIONS(self) -> None:
        self._record("OPTIONS")

    def log_message(self, format: str, *args: Any) -> None:
        pass  # silenciar logs


class OOBServer:
    """
    Servidor OOB local (HTTP) para pruebas y auditorias autorizadas.

    Arranca en 127.0.0.1 en un puerto efimero con un hilo daemon. Cada
    peticion recibida se registra como callback asociada al
    interaction_id del primer segmento de la ruta.

    Uso:
        with OOBServer() as oob:
            oob_id = oob.new_interaction()
            url = oob.url_for(oob_id)
            # ... inyectar url en el payload y disparar la peticion ...
            callback = oob.wait_for_callback(oob_id, timeout=5.0)
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port: int = 0
        self._server: Optional[_OOBHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._callbacks: Dict[str, List[OOBCallback]] = {}

    def start(self) -> str:
        """Arranca el servidor y devuelve la URL base."""
        if self._server is not None:
            return self.base_url
        self._server = _OOBHTTPServer((self.host, 0), self)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    @property
    def base_url(self) -> str:
        return "http://" + self.host + ":" + str(self.port)

    def new_interaction(self) -> str:
        """Genera un identificador unico de interaccion (payload-id)."""
        return uuid.uuid4().hex[:12]

    def url_for(self, interaction_id: str, suffix: str = "") -> str:
        """URL de interaccion para un interaction_id dado."""
        path = interaction_id + (("/" + suffix.lstrip("/")) if suffix else "")
        return self.base_url + "/" + path

    def record_callback(self, callback: OOBCallback) -> None:
        """Registra un callback (thread-safe)."""
        with self._lock:
            self._callbacks.setdefault(callback.interaction_id, []).append(callback)

    def get_callbacks(self, interaction_id: str) -> List[OOBCallback]:
        """Copia de los callbacks registrados para una interaccion."""
        with self._lock:
            return list(self._callbacks.get(interaction_id, []))

    def wait_for_callback(
        self,
        interaction_id: str,
        timeout: float = 5.0,
        poll_interval: float = 0.05,
    ) -> Optional[OOBCallback]:
        """Espera (polling) el primer callback de una interaccion."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            callbacks = self.get_callbacks(interaction_id)
            if callbacks:
                return callbacks[0]
            time.sleep(poll_interval)
        return None

    def stop(self) -> None:
        """Detiene el servidor de forma limpia."""
        server = self._server
        if server is not None:
            server.shutdown()
            server.server_close()
            self._server = None
            self._thread = None

    def __enter__(self) -> "OOBServer":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


class OOBClient:
    """
    Cliente OOB generico para servidores remotos compatibles (interactsh-like).

    Recibe por inyeccion new_interaction, url_for y fetch_callbacks
    (por ejemplo, una funcion que consulte la API del servidor OOB a
    traves del ScopeManager). Asi el modulo queda offline-friendly y
    testeable sin red, y OOBServer/OOBClient comparten interfaz.
    """

    def __init__(
        self,
        new_interaction: Callable[[], str],
        url_for: Callable[[str], str],
        fetch_callbacks: Callable[[str], List[OOBCallback]],
    ) -> None:
        self._new_interaction = new_interaction
        self._url_for = url_for
        self._fetch_callbacks = fetch_callbacks

    def new_interaction(self) -> str:
        return self._new_interaction()

    def url_for(self, interaction_id: str) -> str:
        return self._url_for(interaction_id)

    def get_callbacks(self, interaction_id: str) -> List[OOBCallback]:
        return self._fetch_callbacks(interaction_id)

    def wait_for_callback(
        self,
        interaction_id: str,
        timeout: float = 5.0,
        poll_interval: float = 0.05,
    ) -> Optional[OOBCallback]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            callbacks = self.get_callbacks(interaction_id)
            if callbacks:
                return callbacks[0]
            time.sleep(poll_interval)
        return None
