# Changelog

## 2.2.0-alpha — 2026-11-08 (en desarrollo)

Proyecto unificado bajo una única versión **v2.2**. Fases 1 a 5 del plan completadas.

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

**v2.2 es feature-complete.** Pendiente: tag v2.2.0-alpha + GitHub Release (issue #4).

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
