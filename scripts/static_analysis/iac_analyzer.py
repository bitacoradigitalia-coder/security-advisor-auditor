"""
IaCAnalyzer para Security Advisor Auditor v2.3 (mejora M13).

Analisis estatico offline de Infraestructura como Codigo y CI/CD:
- Dockerfile (DOCK001-DOCK004)
- Kubernetes / docker-compose (K8S001-K8S004)
- Terraform (TF001-TF003)
- GitHub Actions (GHA001-GHA004)

Reutiliza el motor de reglas compartido (regex_rules.RuleEngine). El
dispatch es por familia: nombre de archivo (Dockerfile), extension
(.tf/.hcl) y marcadores de contenido para YAML (k8s, GitHub Actions,
compose). K8S003 y TF002 son comprobaciones de AUSENCIA a nivel de
archivo (fuera del motor lineal). Los comentarios (#) se descartan
antes de escanear para evitar falsos positivos.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union

from .base_analyzer import Finding, ScanResult
from .js_analyzer import JavaScriptAnalyzer
from .regex_rules import Rule, RuleEngine

DOCKERFILE_RULES: List[Rule] = [
    Rule(
        rule_id="DOCK001", title="Contenedor ejecutando como root",
        category="container_misconfiguration", severity="high", confidence="high",
        pattern=r"USER\s+root\b",
        message="El contenedor se ejecuta como root: escape de contenedor = root en el host",
        remediation="Crear un usuario sin privilegios y usar USER <usuario>",
        tags=["owasp:a05"],
    ),
    Rule(
        rule_id="DOCK002", title="Secreto hardcodeado en Dockerfile",
        category="hardcoded_secret", severity="critical", confidence="medium",
        pattern=r"(ENV|ARG|RUN\s+export)\s+[^\n]*(password|passwd|secret|token|api[_-]?key)[\s=]*=[^\s$][^\n]*",
        message="Posible credencial escrita en el Dockerfile (queda en las capas de la imagen)",
        remediation="Inyectar secretos en runtime (env/mounts), nunca en build",
        tags=["secrets", "owasp:a07"], case_insensitive=True,
    ),
    Rule(
        rule_id="DOCK003", title="ADD de una URL remota",
        category="supply_chain", severity="high", confidence="medium",
        pattern=r"^ADD\s+(https?://|[^\s]+@)",
        message="ADD de URL remota: descarga no verificada en build (supply chain)",
        remediation="Descargar con verificacion (checksum) en un RUN o usar COPY de fuentes locales",
        tags=["supply-chain"],
    ),
    Rule(
        rule_id="DOCK004", title="Imagen flotante (:latest o sin tag)",
        category="container_misconfiguration", severity="medium", confidence="high",
        pattern=r"FROM\s+\S+:latest\b|^FROM\s+\S+\s*$",
        message="FROM :latest (o sin tag): builds no reproducibles y actualizaciones no controladas",
        remediation="Fijar la imagen por digest o version exacta (FROM python:3.10.13)",
        tags=["supply-chain"],
    ),
]

K8S_RULES: List[Rule] = [
    Rule(
        rule_id="K8S001", title="Contenedor privilegiado",
        category="container_misconfiguration", severity="critical", confidence="high",
        pattern=r"privileged\s*:\s*true",
        message="privileged: true da acceso casi total al host al contenedor",
        remediation="Eliminar privileged y conceder solo los permisos necesarios",
        tags=["owasp:a05"],
    ),
    Rule(
        rule_id="K8S002", title="Red/puertos del host expuestos",
        category="container_misconfiguration", severity="high", confidence="high",
        pattern=r"(hostPort|hostNetwork|network_mode\s*:\s*host)",
        message="El contenedor usa red o puertos del host (bypass del aislamiento de red)",
        remediation="Publicar puertos via Service/Ingress; evitar hostNetwork/hostPort",
        tags=["owasp:a05"],
    ),
    Rule(
        rule_id="K8S004", title="Capabilities peligrosas anadidas",
        category="container_misconfiguration", severity="high", confidence="medium",
        pattern=r"ADD\s*:?\s*\[?\s*(NET_ADMIN|SYS_ADMIN|ALL|AUDIT_WRITE|DAC_OVERRIDE)\b",
        message="Capabilities peligrosas (p.ej. NET_ADMIN, SYS_ADMIN) concedidas al contenedor",
        remediation="Usar drop: [ALL] y anadir solo las capabilities imprescindibles",
        tags=["owasp:a05"],
    ),
]

TERRAFORM_RULES: List[Rule] = [
    Rule(
        rule_id="TF001", title="Acceso abierto 0.0.0.0/0",
        category="network_exposure", severity="high", confidence="high",
        pattern=r"0\.0\.0\.0/0",
        message="Regla de ingress/acceso abierta a Internet (0.0.0.0/0)",
        remediation="Restringir cidr_blocks a los rangos necesarios",
        tags=["owasp:a05"],
    ),
    Rule(
        rule_id="TF003", title="Recurso expuesto publicamente",
        category="network_exposure", severity="high", confidence="medium",
        pattern=r"(acl|public)\s*=\s*"?(public|true)",
        message="Recurso marcado como publico (acl public / public = true)",
        remediation="Desactivar el acceso publico; usar politica de acceso explicita",
        tags=["owasp:a01"], case_insensitive=True,
    ),
]

GHA_RULES: List[Rule] = [
    Rule(
        rule_id="GHA001", title="pull_request_target con codigo externo",
        category="ci_cd_hijacking", severity="critical", confidence="medium",
        pattern=r"pull_request_target",
        message="pull_request_target ejecuta con secretos accesibles; con checkout del PR = inyeccion de codigo",
        remediation="Evitar pull_request_target o no hacer checkout de refs del PR",
        tags=["owasp:a08", "supply-chain"],
    ),
    Rule(
        rule_id="GHA002", title="Inyeccion de expresiones de evento en run",
        category="ci_cd_hijacking", severity="high", confidence="high",
        pattern=r"run\s*:.*\$\{\{\s*(github\.event|github\.head_ref|github\.ref|github\.sha)",
        message="Expresion de evento interpolada directamente en un bloque run: inyeccion de comandos via titulo/branch del PR",
        remediation="Pasar las expresiones por env y usar una variable de entorno en el script",
        tags=["owasp:a03", "supply-chain"],
    ),
    Rule(
        rule_id="GHA003", title="Permisos amplios (write-all)",
        category="ci_cd_hijacking", severity="high", confidence="high",
        pattern=r"permissions\s*:\s*write-all|write-all",
        message="GITHUB_TOKEN con write-all: un paso comprometido puede escribir el repo",
        remediation="Declarar permissions minimos por job (principio de minimo privilegio)",
        tags=["owasp:a01"],
    ),
    Rule(
        rule_id="GHA004", title="Secretos interpolados en bloques run/env",
        category="secrets_exposure", severity="medium", confidence="medium",
        pattern=r"(env|with|run)\s*:.*\$\{\{\s*secrets\.|^\s*[A-Za-z_][\w-]*\s*:\s*\$\{\{\s*secrets\.",
        message="Secreto interpolado en env/run: los scripts y procesos hijos pueden leerlo (posible volcado a logs)",
        remediation="Minimizar el uso de secrets; nunca hacer echo/env-export hacia logs",
        tags=["secrets"],
    ),
]

ALL_IAC_RULES: List[Rule] = DOCKERFILE_RULES + K8S_RULES + TERRAFORM_RULES + GHA_RULES


class IaCAnalyzer(JavaScriptAnalyzer):
    """Analizador IaC/CI-CD nativo: offline, sin dependencias externas."""

    TOOL_NAME = "iac_native"
    SUPPORTED_LANGUAGES = ["docker", "dockerfile", "yaml", "yml", "terraform", "hcl", "k8s"]
    LANGUAGE = "iac"

    def __init__(self) -> None:
        super().__init__()
        self.engines: Dict[str, RuleEngine] = {
            "docker": RuleEngine(self.TOOL_NAME, self.LANGUAGE, DOCKERFILE_RULES),
            "k8s": RuleEngine(self.TOOL_NAME, self.LANGUAGE, K8S_RULES),
            "tf": RuleEngine(self.TOOL_NAME, self.LANGUAGE, TERRAFORM_RULES),
            "gha": RuleEngine(self.TOOL_NAME, self.LANGUAGE, GHA_RULES),
        }

    @classmethod
    def default_rules(cls) -> List[Rule]:
        return list(ALL_IAC_RULES)

    def _strip_comments(self, content: str) -> str:
        """Elimina lineas de comentario (#) de Dockerfile/YAML/Terraform."""
        return "\n".join(line for line in content.splitlines() if not line.strip().startswith("#"))

    def _absence_finding(self, rule_id: str, title: str, severity: str, message: str, remediation: str, file_path: str) -> Finding:
        return Finding(
            id=rule_id + ":" + file_path + ":0",
            tool=self.TOOL_NAME, language=self.LANGUAGE,
            severity=severity, confidence="medium",
            type="vulnerability" if severity in ("critical", "high") else "risk",
            category="container_misconfiguration",
            title=title, message=message,
            description=message + ". Comprobacion de ausencia a nivel de archivo.",
            file=file_path, line=0, column=0, code="", evidence="<ausencia de atributo>",
            remediation=remediation, fix=remediation, references=[], tags=[rule_id],
        )

    def analyze_file(self, file_path: Union[str, Path]) -> List[Finding]:
        path = Path(file_path)
        name = path.name.lower()
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: List[Finding] = []
        code = self._strip_comments(content)

        if "dockerfile" in name:
            return self.engines["docker"].scan_code(code, file_path=str(path))

        if path.suffix in (".tf", ".hcl"):
            findings.extend(self.engines["tf"].scan_code(code, file_path=str(path)))
            # TF002 (ausencia): bucket S3 sin configuracion de cifrado
            if "aws_s3_bucket" in code and "server_side_encryption" not in code:
                findings.append(self._absence_finding(
                    "TF002", "Bucket S3 sin cifrado en reposo", "high",
                    "Recurso aws_s3_bucket sin aws_s3_bucket_server_side_encryption_configuration",
                    "Anadir aws_s3_bucket_server_side_encryption_configuration con AES256 o KMS",
                    str(path),
                ))
            return findings

        if path.suffix in (".yml", ".yaml"):
            is_gha = "jobs:" in code and ("uses:" in code or "runs-on" in code)
            if is_gha or ".github" in path.parts:
                findings.extend(self.engines["gha"].scan_code(code, file_path=str(path)))
                return findings
            is_k8s = ("apiVersion" in code or "kind:" in code) or "services:" in code
            if is_k8s:
                findings.extend(self.engines["k8s"].scan_code(code, file_path=str(path)))
                # K8S003 (ausencia): pods con contenedores sin runAsNonRoot
                if "containers:" in code and "runAsNonRoot" not in code:
                    findings.append(self._absence_finding(
                        "K8S003", "Contenedor sin runAsNonRoot", "high",
                        "El manifiesto define contenedores sin runAsNonRoot: true (posible root por defecto)",
                        "Anadir securityContext.runAsNonRoot: true (y runAsUser no privilegiado)",
                        str(path),
                    ))
            return findings

        return findings

    def analyze_directory(self, dir_path: Union[str, Path], languages: Optional[List[str]] = None) -> ScanResult:
        root = Path(dir_path)
        if not root.exists():
            return ScanResult(target=str(root), tool=self.TOOL_NAME, language=self.LANGUAGE, findings=[], errors=["Directorio no encontrado: " + str(root)], success=False)
        all_findings: List[Finding] = []
        errors: List[str] = []
        scanned = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            name = path.name.lower()
            if "dockerfile" not in name and path.suffix not in (".yml", ".yaml", ".tf", ".hcl"):
                continue
            scanned += 1
            try:
                all_findings.extend(self.analyze_file(path))
            except OSError as exc:
                errors.append("Error leyendo " + str(path) + ": " + str(exc))
        return ScanResult(
            target=str(root),
            tool=self.TOOL_NAME,
            language=self.LANGUAGE,
            findings=all_findings,
            statistics={"files_scanned": scanned, "by_severity": self._count_by_severity(all_findings)},
            errors=errors,
            success=True,
        )
