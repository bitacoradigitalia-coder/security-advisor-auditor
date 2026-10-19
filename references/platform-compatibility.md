# Compatibilidad y evidencia (consulta oficial: 2026-10-10)

Un solo SKILL.md portable. Los perfiles del instalador únicamente cambian rutas;
no duplican instrucciones ni registran MCP, comandos o permisos globales.
Python es opcional para revisión por el agente; 3.10+ para helpers e instalador.
Git/ripgrep/scanners son opcionales. Si no hay terminal, leer archivos con las
herramientas del anfitrión y registrar lo que no pudo verificarse.

| Agente | Carpeta global por defecto | Descubrimiento/activación | Evidencia |
| --- | --- | --- | --- |
| Hermes | `~/.hermes/skills` | skills_list / skill_view; petición por nombre | [Skills System](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills/) |
| OpenClaw | `~/.openclaw/skills` | carpeta compartida; skills list; petición por nombre | [Skills](https://docs.openclaw.ai/tools/skills) |
| OpenCode | `~/.config/opencode/skills` | skill tool por nombre; permisos del cliente | [Agent Skills](https://opencode.ai/docs/skills/) |
| Codex | `~/.agents/skills` | selector o `$security-advisor-auditor` | [Build skills](https://developers.openai.com/codex/skills/) |
| Claude Code | `~/.claude/skills` | `/security-advisor-auditor` | [Extend Claude](https://code.claude.com/docs/en/skills) |

Se verifica el formato y ciclo de copia/update/desinstalación con perfiles en
directorios temporales Windows. Esto NO acredita carga/activación ni ejecución
de auditoría dentro de clientes reales. `runtime_verified=false` en perfiles.
Hermes, OpenClaw, OpenCode y Claude no están disponibles en PATH en este entorno;
Codex está presente pero no se ha instalado la skill en un perfil real.
Linux/macOS: diseño con pathlib/biblioteca estándar; pruebas nativas pendientes.

Rutas personalizadas, perfiles Hermes y configuraciones particulares de otros
clientes: indicar `--skills-dir` explícitamente; no se inferirán variables ni
se leerán configuraciones privadas. Es el padre de la carpeta de la skill.
OpenCode XDG/config personalizado: usar el override correspondiente. Otros
clientes Agent Skills: copiar el paquete completo a su ruta documentada; no hay
opción `--agent` genérica sin especificación verificable.

Hermes: toolsets y permisos condicionan terminal/web; no restringir la skill
entera por carecer de Python. OpenClaw: sin gating obligatorio, revisión manual
disponible; instalaciones globales pueden filtrarse por allowlists y sandbox.
OpenCode: permisos `skill` y herramientas del agente pueden impedir la carga.
Codex/Claude: controles de confianza/sandbox siguen aplicando; metadatos OpenAI
solo los consume ese cliente. No se ha declarado compatibilidad de Cowork/cloud.

Aceptación manual pendiente por cliente: instalar en perfil aislado, reiniciar o
refrescar el índice según el cliente, pedir la skill por nombre, verificar que
lee las referencias y audita un fixture sin ejecutarlo, registrar versión,
herramientas, informe y resultado. No elevar compatibilidad solo por copiar.
