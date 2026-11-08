# IaC / CI-CD Analyzer (M13)

`IaCAnalyzer` (`scripts/static_analysis/iac_analyzer.py`, tool `iac_native`) analiza offline Infraestructura como Codigo y pipelines CI/CD.

## Familias y reglas

| Familia | Archivos | Reglas |
|---|---|---|
| Dockerfile | nombre contiene `dockerfile` | DOCK001 root, DOCK002 secretos, DOCK003 ADD de URL, DOCK004 :latest/sin tag |
| K8s / compose | .yml/.yaml con apiVersion/kind:/services: | K8S001 privileged, K8S002 hostPort/hostNetwork, K8S003 (ausencia) runAsNonRoot, K8S004 capabilities ADD |
| Terraform | .tf/.hcl | TF001 0.0.0.0/0, TF002 (ausencia) bucket sin cifrado, TF003 public=true/acl public |
| GitHub Actions | .yml con jobs:+uses:/runs-on, o bajo .github/workflows/ | GHA001 pull_request_target, GHA002 interpolacion de evento en run, GHA003 write-all, GHA004 secrets en env/run |

Notas de diseno:
- K8S003 y TF002 son comprobaciones de AUSENCIA a nivel de archivo (no encajan en el motor lineal de reglas).
- Los comentarios (#) se descartan antes de escanear para evitar falsos positivos.
- GHA004 es una senal (medium): `with:` con secrets es practica habitual; revisar el contexto.

## Dogfooding

Analisis del propio repo (2026-11-08, M13): ci-tests.yml y security-audit.yml no usan pull_request_target, ni write-all, ni interpolan expresiones de evento en bloques run, ni usan secrets. bugbounty.yml usa inputs controlados. No hay Dockerfiles ni Terraform en el repo. Conclusion: 0 hallazgos propios; mantener esta revision al tocar cualquier workflow.
