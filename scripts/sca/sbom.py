"""
SBOM CycloneDX 1.5 para Security Advisor Auditor v2.3 (mejora M12).

Genera un SBOM (JSON) desde requirements.txt (dependencias declaradas).
La generacion es DETERMINISTA (sin timestamps) para que los tests y el
diff de commits sean estables.
"""
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# "requests>=2.31.0  # comment" -> name + spec
_REQ_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*([<>=!~][^\s#;]*|\[[^\]]+\])?\s*(?:[#;].*)?$')


def parse_requirements(path: Any) -> List[Dict[str, str]]:
    """Parsea requirements.txt -> [{'name': ..., 'spec': ...}] (comentarios y lineas vacias fuera)."""
    requirements_path = Path(path)
    text = requirements_path.read_text(encoding="utf-8")
    entries: List[Dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = _REQ_RE.match(line)
        if not match:
            continue
        name = match.group(1).lower()
        spec = (match.group(2) or "").strip()
        if spec.startswith("["):  # extras: requests[socks]>=...
            spec = ""
        entries.append({"name": name, "spec": spec})
    return entries


def pinned_version(spec: str) -> Optional[str]:
    """Version exacta si el spec la fija (==X.Y.Z); si no, None."""
    spec = spec.strip()
    if spec.startswith("=="):
        return spec[2:].strip()
    return None


def lower_bound_version(spec: str) -> str:
    """
    Version minima plausible admitida por el spec (heuristica para SCA):
    '==X' -> X; '>=X' -> X; '~=' -> X; '!=...' se ignora; sin cota -> '0'.
    """
    spec = spec.strip()
    if not spec:
        return "0"
    if spec.startswith("==") or spec.startswith(">=") or spec.startswith("~="):
        return spec[2:].strip()
    if spec.startswith(">"):
        return spec[1:].strip()
    return "0"


class SBOMGenerator:
    """Generador de SBOM CycloneDX 1.5 (JSON) desde requirements.txt."""

    def __init__(self, project_name: str = "security-advisor-auditor") -> None:
        self.project_name = project_name

    def from_requirements(self, path: Any) -> "SBOMGenerator":
        self.components = parse_requirements(path)
        return self

    def to_dict(self) -> Dict[str, Any]:
        components: List[Dict[str, Any]] = []
        for entry in self.components:
            components.append({
                "type": "library",
                "bom-ref": "pkg:pypi/" + entry["name"],
                "name": entry["name"],
                "version": pinned_version(entry["spec"]) or lower_bound_version(entry["spec"]),
                "purl": "pkg:pypi/" + entry["name"],
                "properties": [
                    {"name": "sca:declared-spec", "value": entry["spec"] or "*"},
                ],
            })
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "bom-ref": "pkg:generic/" + self.project_name,
                    "name": self.project_name,
                },
            },
            "components": components,
        }

    def to_json(self, path: Any) -> Any:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        return out
