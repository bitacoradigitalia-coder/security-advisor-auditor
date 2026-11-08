# Changelog

## 2.3.0 (en desarrollo)

### Mejoras v2.3

11. **M11 — Canal OOB para vulnerabilidades ciegas** (2026-11-08, CI #73 verde): `scripts/core/oob.py` (`OOBServer` HTTP en 127.0.0.1 puerto efímero con stdlib, callbacks con timestamp e interaction_id; `OOBClient` genérico interactsh-like con fetch inyectado) y `scripts/pentesting/oob_scanner.py` (`OOBScanner` con payloads ciegos SSRF/XXE/RCE, validación de scope/engagement, findings CONFIRMED con evidencias de interacción + callback). Laboratorio extendido con `/fetch?url=` (SSRF ciego). Tests E2E en `tests/test_oob.py`. Fix de dos bugs de CI detectados por el laboratorio: tests order-independientes (unittest ejecuta en orden alfabético) y doble import `core`/`scripts.core` evitado (enums no comparables por módulos distintos).

12. **M12 — SCA: SBOM + advisories** (2026-11-08, CI #75 verde): `scripts/sca/sbom.py` (SBOM CycloneDX 1.5 determinista desde requirements.txt), `scripts/sca/osv_client.py` (`OSVClient` offline por defecto con caché versionada `advisories.json`, modo online opt-in contra OSV.dev con validación de ScopeManager), `scripts/sca/scanner.py` (`SCAScanner`: advisory → finding CONFIRMED con severidad, CWE y fix sugerido), `scripts/sca/cli.py` (CLI propia: `--requirements`, `--output`, `--online`). Tests en `tests/test_sca.py` con fixture `tests/fixtures/sca/`. Desviaciones documentadas: priorización por AIEngine diferida y CLI propia en vez de subcomando de audit.py.

13. **M13 — Escaneo IaC y CI/CD** (2026-11-08, CI #85 verde): `scripts/static_analysis/iac_analyzer.py` (`IaCAnalyzer`, tool `iac_native`) reutilizando el `RuleEngine` compartido, con dispatch por familia (nombre de archivo, extensión, marcadores de contenido): Dockerfile (DOCK001-004), K8s/compose (K8S001-004, con K8S003 runAsNonRoot ausente como check de archivo), Terraform (TF001-003, con TF002 bucket sin cifrado como check de archivo) y GitHub Actions (GHA001-004). Comentarios (`#`) descartados antes de escanear. Registrado en `static_analysis` (lenguajes docker/yaml/terraform/hcl/k8s/iac). Fixtures `tests/fixtures/iac/` (5) y `tests/test_iac_analyzer.py` (10 tests). Dogfooding documentado en `docs/iac.md`. Fixes de iteración: TF003 con raw string de comillas simples (SyntaxError con comilla doble anidada) y fixture deployment.yaml completado con `privileged: true`.

## 2.2.0-alpha — 2026-11-08 (publicada)

Proyecto unificado bajo una única versión **v2.2**. Fases 1 a 5 del plan completadas.

### Mejoras 1-6 post-feature-complete (2026-11-08, CI verde tras cada una)

1. **CI verde**: workflow final limpio (pytest bloqueante, mypy advisory).
2. **Benchmark de falsos positivos**: `tests/test_fp_benchmark.py` mide FP/(FP+TP) < 10% (criterio FASE 2) sobre corpus versionado `tests/fixtures/benchmark/` (6 limpios + 8 vulnerables). Métrica actual: 0%.
3. **Laboratorio vulnerable autorizado**: app deliberadamente insegura con `http.server` en 127.0.0.1 (`tests/lab/vulnerable_app.py`) + test de integración E2E del ActiveScanner: descubrimiento de endpoints (robots.txt), detección de vulnerabilidades (cabeceras, cookies, debug) y findings con evidencia.
4. **Reglas JS afinadas**: JS006 (SQLi) sin falsos positivos en concatenaciones normales, JS009 excluye hosts de especificaciones, JS013 pasa a info; nuevas JS016 (open redirect) y JS017 (setTimeout/setInterval con string).
5. **Analizador nativo PHP**: `PHPAnalyzer` con 8 reglas PHP001-PHP008, registrado en `static_analysis` como `php_native`, con `analyze_directory` limitado a `.php`/`.phtml`.
6. **IA**: deduplicación automática de hallazgos idénticos (clave conservadora: nombre, tipo, objetivo, endpoint, parámetro, payload y estado de verificación) y bono +10 de riesgo en endpoints sensibles (/login, /admin, /api/auth, etc.) con signal `sensitive_endpoint`.

### Mejoras 7-10 post-feature-complete (2026-11-08)

7. **Workflows reparados**: `security-audit.yml` reescrito (YAML válido, escaneo activo solo manual con opt-in, steps tolerantes a fallos); `bugbounty.yml` reescrito (inputs de schema correctos, artifact v4, helper `scripts/bugbounty/ci_actions.py`); fix del test E2E del laboratorio (robots.txt revela `/debug`).
8. **Deuda mypy eliminada**: corregidos los 8 errores heredados en `evidence_engine.py`, `scope_manager.py` (incl. `import time`) y `engagement_manager.py`; mypy pasa a ser bloqueante en CI con 0 errores.
9. **README pulido**: reparados los saltos de línea a mitad de palabra heredados de la corrupción de commits; contador de tests y descripciones de fases actualizados (PHP nativo, IA con deduplicación).
10. **Release**: tag `v2.2.0-alpha` + GitHub Release publicados (d1e7ffd, issue #4 cerrado).

### Reparación de estabilidad (2026-11-08, CI verde)

- CI Tests verde: 182 pasados, 2 saltados (run #19).
- Restaurados archivos con líneas corruptas (saltos a mitad de palabra) en `scripts/core` y `scripts/static_analysis` desde commits limpios previos.
- Corregido SyntaxError del patrón JS006 de `js_analyzer.py` (comillas sin escapar).
- `RuleEngine`: nuevo campo `scan_comments` en `Rule`; la regla TS002 (`@ts-ignore`) ahora evalúa comentarios.
- `AIEngine`: acción recomendada de falso positivo ahora menciona "falso positivo".
- `requirements.txt`: añadido `pyyaml` (importado por `nuclei_analyzer.py`).
- `tests/conftest.py`: hace importables los módulos auxiliares de `tests/` (precision_cases).
- Workflow final: `pip install -r requirements.txt`, pytest bloqueante y mypy advisory (8 errores heredados en código preexistente anotados como deuda).

### Fases del plan v2.2

- FASE 1 (Seguridad del auditor): `ScopeManager` (control de alcance, bloqueo de localhost/redes privadas/metadata, rate limiting, kill switch) y `EngagementManager` (autorizaciones con expiración y almacenamiento cifrado), integrados en scanner, fuzzer, exploit y auth; flags CLI `--scope-config`, `--engagement-id`
- FASE 2 (Fiabilidad): `EvidenceEngine` (evidencias con redacción de secretos, IDs únicos, persistencia) y `VerificationEngine` (estados CANDIDATE/PROBABLE/CONFIRMED, detección de falsos positivos), integrados en scanner, fuzzer y exploit
- FASE 3 (Calidad): `requirements.txt` auditado, anotaciones de tipo en `scripts/core`, `mypy.ini` pragmático, workflow CI con pytest + mypy
- FASE 4 (Multilenguaje): analizadores nativos offline JavaScriptAnalyzer (15 reglas) y TypeScriptAnalyzer (4 reglas TS), motor de reglas compartido (`regex_rules.py`), integrados en `get_analyzer()` (issue #2)
- FASE 5 (IA): `AIEngine` heurístico offline con interpretación contextual, priorización automática P0-P4, riesgo 0-100 con justificación auditable, correlación de hallazgos e informe resumen (issue #3)

**v2.2 es feature-complete y publicada como v2.2.0-alpha.**

## 2.1.1 — 2026-11-02

- Corregidos errores de sintaxis en scripts/audit.py (escape sequence inválido en PoC generator)
- Eliminado `required=True` de argumento positional en comando poc
- Corregido manejo de directorios en comando report para compatibilidad con tests
- Cambiado formato default de reporte de 'markdown' a 'json' para mantener compatibilidad
- Mejorado el manejo de rutas de salida para diferentes formatos de reporte
- Todos los tests (156) pasan correctamente (2 skipped)

## 2.1.0 — 2026-10-11

- AST/flujo Python con fuentes, propagación, guards y mitigaciones por contexto.
- Estados comprobables, trazas y distinción debilidad/explotación confirmada.
- Autorización Flask/Flask-Login y formas de consulta propietario/tenant; JWT acotado.
- QUICK/STANDARD/DEEP, parser en subproceso con límites de tiempo/memoria.
- Esquema con extensiones opcionales y exportación --legacy-report.
- Fixtures, baseline v2.0.1 congelado, evaluación por categoría y regresiones.
- Metodología íntegra, instalador, cinco perfiles y controles previos preservados.
- Límites y evidencias reales en docs/architecture.md, coverage.md y evaluation.md.

## 2.0.1 — 2026-10-10

- Corregida identificación de fuentes descargadas: carpeta de cualquier nombre, sufijos `-main`/versión, padre con raíz única y ZIP mediante `--source`. Metadatos y metodología verifican identidad; instalación con nombre estándar.
- Fuentes ambiguas/incompletas/enlazadas y ZIP peligrosos se rechazan. El instalador usa sus helpers confiables, no importa ni ejecuta código de la fuente ZIP.
- Integridad documental independiente de CRLF/LF y BOM UTF-8. El texto completo coincide con Git original `5633241`; hash canónico `904d385…928a`. Se conserva el archivo local íntegro; no se actualiza el hash a partir de una coincidencia de encabezados. Procedencia y comparación en `docs/corrections-2.0.1.md`.
- Ampliada suite con nombres fuente, padre, ZIP formato GitHub y nombres arbitrarios, ambigüedad, enlaces, cambios de texto y no ejecución del ZIP. Probado además el ZIP real descargado de GitHub con los cinco perfiles en destinos de prueba.
- Sin cambios de rutas/perfiles, rama `main`, alcance ni 21 fases. Activación real de clientes y pruebas nativas Linux/macOS siguen pendientes.

## 2.0.0 — 2026-10-10

- Preservada íntegramente la metodología original de 21 fases y los criterios técnicos, asesoría, tipos de hallazgo y prompt del contrato original.
- Metadatos Agent Skills: licencia, requisitos opcionales y versión; OpenAI YAML normalizado sin `policy.products` no documentado. Conservada invocación implícita.
- Añadidos motor de triaje estático offline, AST Python y señales de secretos/HTML, cobertura explícita, informes Markdown/JSON y prompt de remediación.
- Añadidos límites, rechazo de enlaces/reparse, extracción ZIP portable, redacción y validación semántica de hallazgos. Sin ejecución del objetivo.
- Instalador por cinco perfiles documentados, dry-run, integridad SHA256, update explícito y desinstalación conservadora con protección de cambios.
- Referencias modulares, guías por dominio y fuentes primarias ampliables.
- Pruebas automatizadas con entradas sintéticas y negativas; no hay credenciales reales en fixtures. Integraciones scanner limitadas a descubrimiento/planes.
- Clientes reales y Linux/macOS pendientes de validación; no se promete pentest, certificación, sandbox de ejecución ni resistencia empírica de modelos a injection.

## Base anterior

Skill de asesoría para cualquier software, metodología 21 fases, metadatos OpenAI, icono y licencia MIT. Sin instalador ni código de análisis automatizado.
