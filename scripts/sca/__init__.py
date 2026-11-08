"""Modulo SCA (Software Composition Analysis) — mejora M12 v2.3."""

from sca.sbom import SBOMGenerator, parse_requirements
from sca.osv_client import Advisory, OSVClient
from sca.scanner import SCAScanner

__all__ = ["SBOMGenerator", "parse_requirements", "Advisory", "OSVClient", "SCAScanner"]
