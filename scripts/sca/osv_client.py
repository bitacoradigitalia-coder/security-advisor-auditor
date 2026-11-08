"""
Cliente de advisories para Security Advisor Auditor v2.3 (mejora M12).

MODO OFFLINE por defecto: consulta una cache local versionada
(scripts/sca/advisories.json) sin red alguna, respetando el modelo
sin-red del proyecto. El modo ONLINE (OSV.dev, API publica sin key) es
OPT-IN explicito (online=True) y, si se pasa un ScopeManager, exige que
api.osv.dev este dentro del alcance autorizado.
"""
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

OSV_API_URL = "https://api.osv.dev/v1/query"

DEFAULT_CACHE_PATH = Path(__file__).resolve().parent / "advisories.json"

# Import dual (preferir core.*; ver PLAN-v2.3 "Tecnicas validadas")
try:
    from core.scope_manager import ScopeManager
except ImportError:
    from scripts.core.scope_manager import ScopeManager  # type: ignore[no-redef]


@dataclass
class Advisory:
    """Un advisory (vulnerabilidad conocida) de un paquete PyPI."""
    advisory_id: str
    package: str
    summary: str
    severity: str  # low | medium | high | critical
    cwe: str
    introduced: str
    fixed: str
    url: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.advisory_id,
            "package": self.package,
            "summary": self.summary,
            "severity": self.severity,
            "cwe": self.cwe,
            "introduced": self.introduced,
            "fixed": self.fixed,
            "url": self.url,
        }


def _version_tuple(version: str) -> List[int]:
    """'2.31.0rc1' -> (2, 31, 0). Prefijos numericos solamente."""
    digits = []
    current = ""
    for char in version.strip():
        if char.isdigit():
            current += char
        elif char == "." and current:
            digits.append(int(current))
            current = ""
        else:
            break
    if current:
        digits.append(int(current))
    return digits or [0]


def _version_lt(left: str, right: str) -> bool:
    lt = _version_tuple(left)
    rt = _version_tuple(right)
    length = max(len(lt), len(rt))
    lt += [0] * (length - len(lt))
    rt += [0] * (length - len(rt))
    return lt < rt


def lower_bound_version_of(spec: str) -> str:
    """Alias de compatibilidad para el scanner."""
    import sca.osv_client as _self  # noqa: F401 (evitado: alias directo abajo)
    return _lower_bound_version(spec)


def _lower_bound_version(spec: str) -> str:
    spec = spec.strip()
    if not spec:
        return "0"
    if spec.startswith("==") or spec.startswith(">=") or spec.startswith("~="):
        return spec[2:].strip()
    if spec.startswith(">"):
        return spec[1:].strip()
    return "0"


def is_affected(version: str, introduced: str, fixed: str) -> bool:
    """True si version esta en [introduced, fixed)."""
    if introduced and _version_lt(version, introduced):
        return False
    if fixed and not _version_lt(version, fixed):
        return False
    return True


class OSVClient:
    """Consulta de advisories: cache local offline (por defecto) u OSV.dev con opt-in."""

    def __init__(
        self,
        cache_path: Optional[Any] = None,
        offline: bool = True,
        scope_manager: Optional["ScopeManager"] = None,
    ) -> None:
        self.offline = offline
        self.scope_manager = scope_manager
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
        self._cache: List[Advisory] = []
        self._load_cache()

    def _load_cache(self) -> None:
        if not self.cache_path.exists():
            self._cache = []
            return
        with self.cache_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        self._cache = [
            Advisory(
                advisory_id=entry["id"],
                package=entry["package"],
                summary=entry.get("summary", ""),
                severity=entry.get("severity", "medium"),
                cwe=entry.get("cwe", ""),
                introduced=entry.get("introduced", "0"),
                fixed=entry.get("fixed", ""),
                url=entry.get("url", ""),
            )
            for entry in data.get("advisories", [])
        ]

    def check(self, package: str, version: str) -> List[Advisory]:
        """Advisories que afectan a package@version."""
        package = package.lower()
        affected = []
        for advisory in self._cache:
            if advisory.package.lower() != package:
                continue
            if is_affected(version, advisory.introduced, advisory.fixed):
                affected.append(advisory)
        if self.offline:
            return affected

        # Modo ONLINE (opt-in): OSV.dev. Requiere alcance autorizado si hay ScopeManager.
        if self.scope_manager is not None:
            try:
                self.scope_manager.validate_target(OSV_API_URL)
            except Exception:
                return affected  # fuera de alcance: solo cache
        try:
            import requests  # import tardio: el modo offline no necesita red

            response = requests.post(
                OSV_API_URL,
                json={"package": {"name": package, "ecosystem": "PyPI"}, "version": version},
                timeout=10,
            )
            if response.status_code != 200:
                return affected
            for vuln in response.json().get("vulns", []):
                advisory_id = vuln.get("id", "OSV-UNKNOWN")
                if any(a.advisory_id == advisory_id for a in affected):
                    continue
                affected.append(Advisory(
                    advisory_id=advisory_id,
                    package=package,
                    summary=vuln.get("summary", ""),
                    severity="high",
                    cwe="",
                    introduced="0",
                    fixed="",
                    url="https://osv.dev/vulnerability/" + advisory_id,
                ))
        except Exception:
            pass  # sin red: la cache offline sigue siendo la respuesta
        return affected
