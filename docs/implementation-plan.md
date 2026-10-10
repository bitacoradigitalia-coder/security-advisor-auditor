# Security Advisor Auditor v2.0 — diseño y plan

## Diagnóstico A (2026-10-10)

Base: `56332414226e2c36dd73cd4d22c0e35c0348c347`. Árbol Git limpio antes
de cambios; siete archivos versionados. No había código ejecutable, instalador,
dependencias ni suite. Skill válida con 21 fases, razonamiento profundo,
clasificación de cinco tipos, asesoría, informe y prompt de remediación.
`agents/openai.yaml` incluía `policy.products`, sin soporte en la referencia
actual consultada. Se conserva invocación implícita, icono y propósito.

Invariantes: conservar byte a byte `references/audit-methodology.md`, LICENSE
e icono; mantener los criterios técnicos del entrypoint. SHA256 metodología:
`0e3076fc257a0d37e388db7af901d45bb6cd83dc5fa3d5dc5d411cd46c73c95d`.
Lectura completa de los siete archivos antes de editar. No hay AGENTS.md local.

## Diseño elegido

Skill estándar como núcleo, paquete Python 3.10+ de biblioteca estándar en
`scripts/security_auditor/`, CLI en `scripts/audit.py`, instalador en la raíz.
Alternativas descartadas: duplicar metodología por cliente (deriva) y exigir
un servidor MCP (dependencias y permisos innecesarios). No se implementa MCP.
Los adaptadores son perfiles de rutas y documentación, no agentes nuevos.
Los módulos son guías de revisión realmente enlazadas, no analizadores ficticios.

El motor produce inventario, señales AST y heurísticas limitadas, candidatos,
las 21 fases y limitaciones. Nunca confirma una coincidencia automáticamente.
No ejecuta código del objetivo ni realiza tráfico de red. Integraciones de
scanners: descubrimiento local y planes de comandos, sin ejecución automática.
El agente completa arquitectura, autorización y lógica mediante la metodología.
Salida fuera del objetivo; sin sobrescritura. ZIP en carpeta nueva, validación
portable, límites y publicación tras extracción completa. Instalación local
con hashes, staging y rechazo de cambios/enlaces; actualización explícita.
No se promete aislamiento de procesos: no hay ejecutor de repositorios.

## Plan B–G y validación

- [x] B: metadatos estándar, referencias de evidencia/ética/reporting y módulos;
  validar nombre, límites, enlaces y preservación de 21 fases.
- [x] C: perfiles Hermes/OpenClaw/OpenCode/Codex/Claude, fuentes oficiales;
  probar instalación/desinstalación/actualización y dry-run en homes temporales.
- [x] D: `safeio.py`, `engine.py`, `reporting.py`, `scanners.py`, CLI y schema;
  pruebas de inventario, AST, secretos sintéticos, negativos y reportes.
- [x] E: enlaces/reparse, traversal, límites, no ejecución/redacción, no overwrite;
  pruebas con archivos maliciosos y ZIP. Instrucciones ajenas son datos.
- [x] F: unittest completo, CLI real, validación skill y diff; registrar resultados.
- [x] G: README español, CHANGELOG, ejemplos y entrega con matriz de evidencia.

Revisión especial: directorios con enlaces, nombres ZIP Windows, manifest
manipulado, archivos extra tras instalación y condiciones desconocidas en
hallazgos confirmados. Se prueban antes de dar por verificados los controles.
No commit, push, despliegue ni instalación en perfiles reales en esta entrega.
Compatibilidad documental y copia local no equivalen a activación del cliente.

## Decisiones y límites de cierre

Implementación local autorizada directamente por el encargo: sin pausas de
aprobación de diseño, sin commit/push ni instalación real. C incluye validación
de perfiles/rutas y copia, no runtime; runtime queda pendiente. D incluye
descubrimiento/condiciones de scanners, no su ejecución. E evita ejecutar
objetivos; no inventa un sandbox. F valida perfil YAML portable mediante código
local; validador genérico externo pendiente por ausencia de PyYAML.
El estado de aceptación detallado y resultados están en `docs/delivery.md`.
