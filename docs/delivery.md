# Entrega v2.0 Universal — 2026-10-10

## Resultado

Evolución del repositorio original, sin reemplazarlo ni reducir metodología.
Nuevo motor offline de triaje, instalador conservador, reportes y referencias.
Preparado para revisión como primera distribución **con límites explícitos**;
no se declara activación real universal ni auditoría automática exhaustiva.
Git inicial limpio, commit base `56332414226e2c36dd73cd4d22c0e35c0348c347`.
No commit, push, publicación, despliegue o instalación en perfiles reales.

## Estructura y archivos

Modificados: `SKILL.md`, `README.md`, `agents/openai.yaml`.
Preservados sin cambios: `references/audit-methodology.md`, `LICENSE`,
`assets/icon.svg`, `.gitattributes`. Metodología SHA256:
`0e3076fc257a0d37e388db7af901d45bb6cd83dc5fa3d5dc5d411cd46c73c95d`.

Creados:

```text
.gitignore
CHANGELOG.md
install.py
adapters/profiles.json
docs/implementation-plan.md
docs/delivery.md
examples/README.md
examples/safe/app.py
examples/safe/client.js
examples/vulnerable/app.py
examples/vulnerable/client.js
modules/api-security.md
modules/business-logic.md
modules/cloud-security.md
modules/code-security.md
modules/dependency-security.md
modules/web-security.md
references/evidence-policy.md
references/ethical-security.md
references/knowledge-index.md
references/platform-compatibility.md
references/reporting-standard.md
schemas/audit-report.schema.json
scripts/audit.py
scripts/security_auditor/__init__.py
scripts/security_auditor/engine.py
scripts/security_auditor/reporting.py
scripts/security_auditor/safeio.py
scripts/security_auditor/scanners.py
scripts/security_auditor/validation.py
tests/test_system.py
```

La distribución incluye documentación, ejemplos y tests enlazados. Excluye Git,
pycache y archivos no pertenecientes al paquete. `scripts/` sigue Agent Skills;
los seis módulos son guías especializadas, no motores fingidos. Los perfiles
solo distinguen rutas; no copian la metodología por cliente.

## Funcionalidades preservadas

Las 21 fases originales: reconocimiento, límites de confianza, autenticación,
autorización, aislamiento, lógica de negocio, secretos, inyección, concurrencia,
abuso, integraciones, privacidad, archivos, criptografía, APIs, clientes,
dependencias, CI/CD, cloud, transporte/despliegue y asesoría de escalabilidad.
Conservados controles profundos sobre idempotencia, propiedad por email,
rotación de tokens, perfiles públicos, costes privilegiados, locks, cross-tenant,
deriva documental y secretos URL; cinco tipos de hallazgo, asesoría económica,
plan incremental y prompt específico con regresión. Español y lectura por defecto.

## Funcionalidades nuevas y trazabilidad

| Requisito | Implementación | Evidencia / límite |
| --- | --- | --- |
| Inspección y preservación | Diagnóstico/plan; metodología intacta | Hash y test de preservación |
| Agent Skills | SKILL, versión/licencia/requisitos, referencias | Validador portable local; parser general pendiente |
| Compatibilidad | Cinco perfiles con fuentes oficiales | Rutas/copia verificadas; runtime no |
| Flujo progresivo | Inventario, señales, 21 estados de cobertura | AST parcial; auth/lógica/contexto requieren agente |
| Hallazgos trazables | JSON y validate_report | Ubicación/CWE/commit/impacto/estado; no certifica verdad del reviewer |
| Herramientas opcionales | capabilities y condiciones de uso | Detecta instaladas/ausentes; no ejecuta scanners |
| Conocimiento local | Índice y módulos propios | Ampliable; no bundle de libros ni advisories actualizados |
| Seguridad del agente | safeio, redacción, literal Markdown, JSON como datos | Tests de no ejecución; resistencia de modelos no medida |
| ZIP | Original filename, límites, staging y rutas portables | Traversal, NUL, ADS, symlink ZIP, colisiones y ratio |
| Instalación | Dry-run, hashes, staging, update y uninstall | Cinco perfiles y protección de cambios/archivos extra/manifest |
| Informes | Markdown, JSON, prompt | CLI scan/report; categorías y doce apartados |
| Pruebas | unittest; fixtures sintéticos/negativos | Resultados de ejecución abajo |
| Documentación | README/CHANGELOG/plan/entrega | Comandos reales y pendientes explícitos |

## Pruebas ejecutadas

Entorno: Windows, Python 3.12.6. Comando:

```text
python -B -m unittest discover -s tests -v
```

La suite contiene 25 tests, incluidos subcasos de cinco perfiles. Se comprueban:
metadatos inválidos, referencia ausente, preservación, CLI con ruta absoluta y
relativa, aliases AST, negativos, secreto sintético redactado y sin duplicación,
clasificación/confirmación, cobertura, literalización, límites por archivo/total,
herramientas ausentes, scan sin escritura ni ejecución, report reexportado,
ZIP traversal/Windows/ADS/NUL/duplicados/colisiones/ratio/tamaño/entradas/corrupto,
dry-run, rutas globales en homes temporales, copia completa, hashes, actualización,
rechazo de cambios/extra/manifest traversal, desinstalación y junctions.

Resultado final: **24 tests aprobados, 1 omitido, 0 fallos**. La prueba de symlink
de archivo fue omitida porque Windows no concede su creación en este contexto.
La prueba de junctions sí se ejecutó y aprobó. No se equipara a pruebas nativas
de symlink Linux/macOS. Se autorizaron temporales para superar una restricción
de limpieza del sandbox; los tests no ejecutan código de objetivos.

CLI real, fuera del árbol Git:

```text
python -B scripts/audit.py validate-skill .
python -B scripts/audit.py tools
python -B scripts/audit.py scan examples/vulnerable --output ../verification-20261010/vulnerable
python -B scripts/audit.py scan examples/safe --output ../verification-20261010/safe
```

Ejemplo vulnerable: cinco candidatos, CWE-95/78/502/295/79, ninguno confirmado.
Ejemplo negativo: cero candidatos; sin declaración de seguridad total.
Se generaron JSON/Markdown/prompt en ambas carpetas. No se ejecutaron fixtures.
CLI report se ejercitó adicionalmente en temporales por la suite.
Git/rg disponibles; Semgrep, Gitleaks, OSV-Scanner y Trivy ausentes.
`git diff --check` sin errores; metodología/licencia/icono sin diferencias.

Validador `skill-creator/scripts/quick_validate.py` intentado: no pudo arrancar
porque falta PyYAML, también ausente en Python empaquetado. No se instaló nada.
Además su whitelist local no contempla `compatibility`, admitido por la
especificación Agent Skills actual. Se ejecutó el validador local del perfil
portable; no se afirma haber ejecutado skills-ref ni un parser YAML general.
JSON Schema Draft 2020-12 se entrega; validación externa con motor genérico
pendiente. La validación semántica local de reports sí está ejecutada.
No hay linter, typecheck ni build preexistentes: no se inventan resultados.

## Compatibilidad comprobada

| Cliente | Fuente oficial/ruta | Ciclo de archivos Windows | Activación real |
| --- | --- | --- | --- |
| Hermes | Verificada documentalmente | Aprobado | No probado; cliente ausente |
| OpenClaw | Verificada documentalmente | Aprobado | No probado; cliente ausente |
| OpenCode | Verificada documentalmente | Aprobado | No probado; cliente ausente |
| Codex | Verificada documentalmente | Aprobado | No probado; binario disponible |
| Claude Code | Verificada documentalmente | Aprobado | No probado; cliente ausente |

Fuentes directas y comandos de activación en
[platform-compatibility](../references/platform-compatibility.md), consultadas el
2026-10-10. Las tablas no equivalen a integración funcional certificada.
Linux/macOS y otros clientes quedan pendientes.

## Comandos de instalación reales

Desde una copia fuente/distribución, no desde la instalación que se intenta borrar:

```text
python install.py --agent hermes --dry-run
python install.py --agent hermes
python install.py --agent openclaw
python install.py --agent opencode
python install.py --agent codex
python install.py --agent claude
python install.py --agent hermes --update
python install.py --agent hermes --uninstall --dry-run
python install.py --agent hermes --uninstall
```

Seleccionar el cliente deseado. Para custom/profile usar `--skills-dir` como padre
y repetirlo en update/uninstall. No modifica configuraciones de los agentes.

## Pendientes y siguiente versión

1. Validar activación y auditoría de fixtures dentro de Hermes/OpenClaw/OpenCode
   en perfiles aislados y guardar versiones/resultados; después Codex/Claude.
2. Ejecutar suite nativa Linux/macOS y symlinks reales. Añadir CI con acciones
   revisadas/pinneadas y validadores independientes de YAML/JSON Schema.
3. Integraciones reales de scanners: versiones, parsers redactados, exit codes,
   reglas confiables, bases offline y consentimiento de red; hoy solo discovery.
4. Ampliar AST/control flow y frameworks con corpus que mida recall/falsos positivos;
   hoy ejemplos de regresión limitados, sin benchmark global.
5. Evaluar prompt injection a nivel de modelos/agentes. Helpers prueban no ejecución,
   no inmunidad del LLM. No se ofrece sandbox ejecutor: usar uno externo antes
   de correr pruebas de terceros.
6. Snapshots inmutables frente a carreras locales; redacción adicional de PII y
   secretos no reconocidos; firma/autenticidad de releases si se publica.

Los límites se documentan como pendientes, no se presentan como funcionalidades
terminadas. No se hicieron escaneos activos ni conexiones cloud o servicios públicos.
