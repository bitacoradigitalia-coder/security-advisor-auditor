# Entrega v2.1 — Inteligencia y precisión

## Resultado y ubicación

Implementación local funcional en rama feature/intelligence-precision-v2.1,
base main 51a3abb (v2.0.1). Sin commit, push, merge ni publicación.
C: se quedó sin espacio durante pruebas; por autorización del usuario se copió
el repositorio con Git a E:/Codex/security-advisor-v2.1/security-advisor-auditor.
Esta copia de E: es la entrega actual; C: conserva una etapa anterior incompleta.
Los temporales y resultados finales se guardan en E:/Codex/security-advisor-v2.1.

## Arquitectura y capacidades

Motor Python offline: estados con evidencia, trazas source/propagation/control/sink,
AST contextual, guards dominantes y correlación DEEP acotada. Modelos de SQL,
comandos, rutas, SSRF, plantillas, HTML seguro, permisos por objeto/tenant y firma
JWT desactivada. QUICK conserva las señales prioritarias; STANDARD/DEEP añaden
contexto. Parser confiable en subproceso con timeout y memoria; no ejecuta el
objetivo. Sin dependencias pip, llamadas IA ni red automática. El razonamiento
complejo del agente no puede confirmar explotación automáticamente.

Conservados: identidad/nombre, licencia, icono, agentes/openai.yaml, 21 fases
originales, validación documental, controles de lectura/ZIP/rutas/enlaces,
secretos/redacción, instalador fuente ZIP/padre/carpeta, cinco perfiles,
dry-run/update/uninstall e informes JSON/Markdown/prompts.
Hash canónico de metodología: 904d385ea10a960b5b0b383b99471fc3250c0f753ef63a3d5a36f86ebeed928a.
install.py, adapters/profiles.json y references/audit-methodology.md sin cambios.

## Clasificación

- CANDIDATE: código sospechoso, sin prueba contextual.
- PROBABLE: condición insegura sustentada por fuente/traza/contexto.
- CONFIRMED: debilidad revisada con ruta, control violado y reproducción.
- FALSE_POSITIVE: hipótesis invalidada por evidencia local; sin certificar el sistema.
- NOT_VERIFIED: faltan datos/capacidad; se conserva evidencia y motivo.

verification.exploitation separa la explotación: not_tested por defecto; confirmed
requiere prueba local ejecutada, resultado, autorización y aislamiento.
La suite comprueba las reglas de promoción y rechazo; no se ha ejecutado una
explotación del producto. Confianza alta no constituye prueba de confirmación.

## Lenguajes, frameworks, límites

Python AST verificado en Windows/Python 3.12. Flask/Flask-Login: modelos de formas
de rutas y consultas, no certificación de versión ni análisis completo de política.
PyJWT: options literal verify_signature=False; uso de claims todavía requiere
revisión. JS/TS conserva triaje HTML, no AST/taint. Otros lenguajes: inventario y
secretos. Especificación detallada, posibles FP/FN y fuentes en coverage.md.

DEEP no es interprocedimental completo: same-file funciones directas acotadas,
sin decoradores/variádicos. Reflexión, herencia, ORM arbitrario, RLS/middleware,
loops/try/with completos, aliases complejos, auth vertical, sesiones/roles y
fuentes indirectas requieren revisión. POSIX preparado, sin ejecución nativa.
Instalación de archivos para cinco perfiles verificada; activación real pendiente.
Timeout de parser duro, inventario cooperativo; memoria de parser y no RSS global.

## Evaluación real

30 fixtures A–E + cinco casos adicionales (28 etiquetados, dos inciertos) y grupo
F en pruebas de robustez. Evaluation-results.json conserva todos los casos,
estados, evidencia, exactitud, TP/FP/FN/TN y métricas por categoría/lenguaje/framework.

| Versión | TP | FP | FN | TN | Precisión | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v2.0.1 | 3 | 3 | 11 | 11 | 50 % | 21,43 % | 30 % |
| v2.1 STANDARD | 14 | 0 | 0 | 14 | 100 % | 100 % | 100 % |

30/30 estados esperados. Ejemplos antes/después en evaluation.md: eval constante,
allowlist de expresiones/comandos; nuevos flujos SQL, path traversal y recursos
sin ámbito local. Este corpus guio el desarrollo; no es benchmark independiente.
No representa precisión general. FP/FN posibles fuera del corpus conservados en
coverage.md; no se ocultan por alcanzar el objetivo del 90 %.

## Compatibilidad de informes

schema_version=2.0 y campos antiguos conservados. Extensiones opcionales para
estados/evidencias/analysis. --legacy-report elimina esos campos para consumidores
estrictos del esquema original; exportación no destructiva verificada. Report,
Markdown y prompt siguen funcionando, separados confirmados e investigación.
El esquema JSON se amplió y el original se conserva como fixture de compatibilidad.
Validación semántica local ejecutada; validador Draft independiente no instalado.
IDs deterministas de ubicación/regla; mover líneas cambia IDs. Nuevo finding.schema
referencia la definición existente. No se asigna CVSS/CVE automáticamente.

## Verificación y riesgos pendientes

Base v2.0.1: 36 pruebas, 35 aprobadas, una omitida por permisos de symlink Windows.
La primera ejecución restringida falló por acceso a temporales; repetida con
permisos apropiados. El intento posterior que agotó C: no se contó como éxito;
se repitió en E:. Resultado final: **61 pruebas, 60 aprobadas y una omitida** por permisos de symlink.
Registro en final-verification.json y ../regression-final.log. Diff check aprobado.
La evaluación final usa el motor integrado STANDARD, IDs estables y validación
de informes para cada proyecto sintético.

Además de los fixtures: guards por ramas, transforms desconocidos, uso/rebinding
antes de autorizar, aliases/imports/globals, early returns, JWT, estados/explotación,
JSON/Markdown/prompts, CLI modos, legacy fields, límites/nodos/bytes/tiempo/memoria,
instalador cinco perfiles, fuentes/ZIP -main/arbitrarias/ambiguas, symlink/junction,
path traversal, integridad/21 fases, redacción y prompt injection como datos.

No declarar lista la seguridad global. Pendientes: benchmark externo autorizado,
validación nativa Linux/macOS, activación en agentes, revisión humana de políticas,
scanners opcionales y verificador JSON Schema independiente. v2.2: CFG/call graph
entre archivos, modelos ORM/RLS/roles/sesiones y parser JS/TS mantenible.

## Archivos añadidos y modificados

- CHANGELOG.md
- README.md
- SKILL.md
- modules/api-security.md
- modules/code-security.md
- references/evidence-policy.md
- references/reporting-standard.md
- schemas/audit-report.schema.json
- scripts/audit.py
- scripts/security_auditor/__init__.py
- scripts/security_auditor/engine.py
- scripts/security_auditor/reporting.py
- scripts/security_auditor/safeio.py
- docs/architecture.md
- docs/coverage.md
- docs/evaluation-results.json
- docs/evaluation.md
- docs/intelligence-plan.md
- schemas/finding.schema.json
- scripts/security_auditor/authorization.py
- scripts/security_auditor/contextual.py
- scripts/security_auditor/dataflow.py
- scripts/security_auditor/isolation.py
- scripts/security_auditor/verification.py
- scripts/security_auditor/worker.py
- tests/baseline-report.schema.json
- tests/baseline_v201.py
- tests/evaluate_precision.py
- tests/fixtures/A1_constant_eval/app.py
- tests/fixtures/A2_external_eval/app.py
- tests/fixtures/A3_unresolved_entry/app.py
- tests/fixtures/A4_effective_validation/app.py
- tests/fixtures/A5_insufficient_validation/app.py
- tests/fixtures/B10_dynamic_fragment/app.py
- tests/fixtures/B6_parameterized/app.py
- tests/fixtures/B7_concatenated/app.py
- tests/fixtures/B8_orm_parameters/app.py
- tests/fixtures/B9_identifier_allowlist/app.py
- tests/fixtures/C11_fixed_argv/app.py
- tests/fixtures/C12_external_shell/app.py
- tests/fixtures/C13_program_arguments/app.py
- tests/fixtures/C14_command_allowlist/app.py
- tests/fixtures/D15_fixed_file/app.py
- tests/fixtures/D16_external_path/app.py
- tests/fixtures/D17_confined_path/app.py
- tests/fixtures/D18_text_prefix/app.py
- tests/fixtures/E19_owner_query/app.py
- tests/fixtures/E20_missing_owner/app.py
- tests/fixtures/E21_authenticated_tenant/app.py
- tests/fixtures/E22_client_tenant/app.py
- tests/fixtures/E23_owner_guard/app.py
- tests/fixtures/E24_authentication_only/app.py
- tests/fixtures/E25_external_middleware/app.py
- tests/fixtures/S1_ssrf/app.py
- tests/fixtures/S2_ssrf_constant/app.py
- tests/fixtures/T1_template/app.py
- tests/fixtures/X1_html/app.py
- tests/fixtures/X2_context_escape/app.py
- tests/fixtures/expected.json
- tests/precision_cases.py
- tests/test_contract.py
- tests/test_precision.py

- docs/delivery-v2.1.md
- docs/final-verification.json
