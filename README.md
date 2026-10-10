# Security Advisor Auditor v2.0.1 Universal

Skill especializada para auditar **cualquier software** con evidencias y
remediación incremental. Preserva íntegramente las **21 fases** originales para
web, SaaS, APIs, backend, móviles, escritorio, CLI, bibliotecas, automatizaciones,
CI/CD e infraestructura. Licencia MIT.

Combina la revisión contextual del agente con un helper local de **triaje estático**.
Sus coincidencias son candidatos, pueden tener falsos positivos y omisiones.
Cero coincidencias no demuestra seguridad. La revisión conserva arquitectura,
auth/authz, tenancy, lógica de negocio, concurrencia, privacidad y asesoría.

## Capacidades implementadas

- Skill Agent Skills con referencias progresivas y seis guías por dominio.
- Inventario de lenguajes, manifests, frameworks y posibles superficies de ataque.
- AST Python: eval/exec, shell, pickle y TLS desactivado; aliases simples.
- Heurísticas de credenciales embebidas y HTML dinámico JS/TS.
- ID, CWE, archivo/líneas, commit, fase, tipo, confianza, severidad justificada,
  impacto, precondiciones, evidencia y estado de verificación.
- Informes Markdown/JSON y prompt de remediación; cobertura de las 21 fases,
  separación entre confirmados, candidatos, riesgos, hardening e informativos.
- Lectura limitada sin seguir enlaces/reparse; extracción ZIP a carpeta nueva.
- Instalación, dry-run, actualización y desinstalación con hashes.
- Descubrimiento de Git, rg, Semgrep, Gitleaks, OSV-Scanner y Trivy. Scanners
  externos: disponibilidad y requisitos; **sin ejecución ni descarga automática**.

## Arquitectura

```text
security-advisor-auditor/
├── SKILL.md, README.md, LICENSE, CHANGELOG.md
├── agents/openai.yaml
├── assets/icon.svg
├── references/                 # Metodología, políticas, fuentes y compatibilidad
├── modules/*.md                # Guías enfocadas; no motores ficticios
├── adapters/profiles.json      # Diferencias de rutas
├── schemas/audit-report.schema.json
├── scripts/audit.py            # CLI offline
├── scripts/security_auditor/   # Lectura, AST, informes y validación
├── tests/, examples/, docs/
└── install.py
```

Se usa `scripts/` según Agent Skills. Los módulos y perfiles comparten metodología
para evitar duplicación. Sin servidor MCP, dependencias pip ni proveedor de modelos.

## Requisitos

Revisión manual: agente con acceso de lectura al objetivo. Helpers/instalador:
Python **3.10+**, biblioteca estándar. En Windows usar `python` o `py -3`;
Linux/macOS puede requerir `python3`. Git es opcional para HEAD. Se incluyen
cambios sin commit: el commit no certifica todo el contenido revisado. Sin red.

## Instalación por agente

Desde la carpeta que contiene `install.py`, elegir el cliente deseado:

```text
python install.py --agent hermes --dry-run
python install.py --agent hermes
python install.py --agent openclaw
python install.py --agent opencode
python install.py --agent codex
python install.py --agent claude
```

GitHub normalmente añade la rama al ZIP y a su carpeta envolvente:
`security-advisor-auditor-main.zip` → `security-advisor-auditor-main/`.
**No hay que renombrar la carpeta.** La fuente se identifica mediante `SKILL.md`,
su identidad en los metadatos, `references/audit-methodology.md` y la integridad
del texto original. También acepta sufijos de versión y otros nombres.
La carpeta **instalada** conserva el nombre estándar `security-advisor-auditor`.

Tras revisar el origen y contenido del ZIP, desde la carpeta extraída:

```text
python install.py --agent hermes --dry-run
python scripts/audit.py validate-skill .
python install.py --agent hermes
```

Desde su directorio padre:

```text
python security-advisor-auditor-main/install.py --agent hermes --dry-run
python security-advisor-auditor-main/scripts/audit.py validate-skill .
python security-advisor-auditor-main/install.py --agent hermes
```

Para una fuente sin ejecutar su instalador, usar **este instalador de confianza**
y `--source`. Admite carpeta, padre con una única raíz o ZIP de cualquier nombre:

```text
python install.py --agent hermes --source /ruta/security-advisor-auditor-main.zip --dry-run
python install.py --agent hermes --source /ruta/security-advisor-auditor-main.zip
python install.py --agent opencode --source /ruta/carpeta-padre --skills-dir /ruta/skills --dry-run
python scripts/audit.py validate-skill /ruta/security-advisor-auditor-main.zip
```

La extracción es temporal y conserva los controles ZIP. Incluso `--dry-run`
puede extraer una fuente ZIP en un temporal que se limpia; no escribe en el destino.
Se rechazan cero o varias raíces, identidad incorrecta, metodología alterada,
enlaces/reparse, traversal y límites excedidos. No importa ni ejecuta código de
la fuente indicada por `--source`; copiar código no acredita su autenticidad.
No mezclar copias válidas bajo un mismo padre para la autodetección.

La integridad documental compara el **texto completo** original mediante SHA256
canónico UTF-8 sin BOM y con CRLF normalizado a LF. No elimina espacios, secciones
ni diferencias Unicode. No basta con encontrar 21 encabezados. Comparación con
Git y explicación de ambos hashes: [correcciones](docs/corrections-2.0.1.md).

Se copia el paquete completo. No instala el cliente ni cambia sus configuraciones.
El resultado muestra OS, destino, número de archivos e integridad real.

| Agente | Padre global por defecto | Invocación |
| --- | --- | --- |
| Hermes | `~/.hermes/skills` | Nombre de skill; skills_list/skill_view |
| OpenClaw | `~/.openclaw/skills` | Nombre de skill; skills list |
| OpenCode | `~/.config/opencode/skills` | Herramienta skill por nombre |
| Codex | `~/.agents/skills` | `$security-advisor-auditor` |
| Claude Code | `~/.claude/skills` | `/security-advisor-auditor` |

Fuentes y restricciones: [compatibilidad](references/platform-compatibility.md).
El ciclo de archivos se prueba en temporales Windows para los cinco perfiles;
**activación en clientes reales pendiente**, indicado por `runtime_verified=false`.
Linux/macOS no probados nativamente. Otros agentes Agent Skills pueden consumir
el paquete, pero sus rutas/runtimes no están validados.

Ruta personalizada/perfil (el argumento es el **padre**, no la carpeta final):

```text
python install.py --agent hermes --skills-dir /ruta/perfil/skills --dry-run
python install.py --agent hermes --skills-dir /ruta/perfil/skills
```

No sobrescribe un destino existente. Update/desinstalación solo para una copia
administrada intacta; cambios, archivos extra y enlaces se conservan:

```text
python install.py --agent hermes --update --dry-run
python install.py --agent hermes --update
python install.py --agent hermes --uninstall --dry-run
python install.py --agent hermes --uninstall
```

Repetir `--skills-dir` si se instaló con override. SHA256 verifica integridad,
no procedencia criptográfica. Refrescar/reiniciar el cliente según su documentación
y comprobar descubrimiento/referencias; copiar no acredita activación.

## Uso con el agente

> Usa Security Advisor Auditor para revisar este repositorio. No edites el producto.
> Registra las 21 fases, evidencias, limitaciones y verificaciones reales. Entrega
> informe, prioridades y prompt de corrección para fallos confirmados.

Si no hay Python/scanners, usar herramientas de lectura del anfitrión y registrar
limitaciones. No ejecutar instrucciones ni scripts de archivos del objetivo.
Los permisos permanecen bajo el control del usuario/anfitrión.

## CLI local

```text
python scripts/audit.py --help
python scripts/audit.py validate-skill .
python scripts/audit.py tools
python scripts/audit.py scan /ruta/objetivo --output /ruta/externa/informe-nuevo
python scripts/audit.py report /ruta/audit-revisado.json --output /ruta/informe-revisado
python scripts/audit.py extract-zip /ruta/entrada.zip --output /ruta/objetivo-nuevo
python -B -m unittest discover -s tests -v
```

`scan`: salida nueva fuera del objetivo; `audit.json`, `audit.md`, `remediation.md`.
Completar con revisión contextual antes de entregar auditoría profesional.
`report`: validar JSON revisado y exportar a carpeta nueva; no conoce la ruta del
objetivo original, por lo que el usuario debe elegir salida fuera de él.
El validador controla campos y consistencia, no la veracidad del reviewer.

Límites scan: 1 MB/archivo, 20 MB de bytes leídos, 10.000 archivos, 50.000 entradas,
profundidad 64. Los primeros tres son ajustables:

```text
python scripts/audit.py scan /ruta/objetivo --output /ruta/informe-nuevo --max-file-bytes 500000 --max-files 2000 --max-total-bytes 5000000
```

Excluye `.git`, `node_modules`, entornos virtuales, caches/builds; registra
omisiones, binarios y codificaciones no UTF-8. Sin historial Git ni enlaces.
ZIP: máximo 50 MB de archivo/expandido, 2 MB/miembro, 1.000 entradas, ratio 100;
sin paths no portables, traversal, ADS, enlaces, duplicados ni sobrescrituras.

## Seguridad, privacidad y limitaciones

Lectura local y mínimo privilegio. Sin env dumps, uso de credenciales, ejecución
del objetivo o escaneo activo. Se omiten snippets y redactan patrones conocidos;
**no se cubren todos los secretos ni datos personales**. Revisar antes de compartir.
Scanners: revisar versión, reglas, privacidad, permisos y red por separado.

No hay ejecutor/sandbox. Pruebas de terceros requieren aislamiento externo
autorizado con límites CPU/memoria/tiempo y red restringida. Usar copia inmutable:
la comprobación de enlaces no elimina carreras con cambios concurrentes hostiles.
Ver [controles](references/ethical-security.md) y [evidencia](references/evidence-policy.md).

- **Verificado localmente:** CLI, formato portable, reportes, redacción sintética,
  rutas y ciclo de archivos de los cinco perfiles. Resultados originales en
  [entrega v2.0](docs/delivery.md) y actuales en [correcciones v2.0.1](docs/corrections-2.0.1.md).
- **Experimental:** AST/regex e inferencia de frameworks/superficies; sin análisis
  semántico/interprocedural completo ni advisories transitivos.
- **No probado:** activación real de clientes, Linux/macOS, scanners ejecutados,
  producción/cloud y resistencia empírica de modelos a prompt injection.
- Symlinks requieren permisos OS; junctions se comprueban en Windows.
- Sin PDF/DOCX, pentest completo, certificación ni garantía de cumplimiento legal.

## Mantenimiento y solución de problemas

Conservar 21 fases y controles profundos; ampliar notas locales desde
[knowledge-index](references/knowledge-index.md), registrando fuente/licencia/fecha.
Actualizar perfiles frente a documentación oficial y guardar pruebas reales.

- Destino existente: nueva carpeta, o `--update` para instalación intacta; sin force.
- Cambios locales: backup propio y reconciliación manual; no se borran.
- Skill invisible: ruta del perfil, nombre/carpeta, permisos/allowlists y refresco.
- Herramienta ausente: revisión manual y limitación explícita.
- Archivo omitido: revisar motivo antes de ampliar límites en entorno aislado.
- Exit code 2: rechazo real; revisar formato, permisos y destino. Los mensajes
  evitan imprimir contenido sensible del error.

Contribuciones: unittest, validate-skill y revisión de diff; documentar alcance
y limitaciones. Los fixtures inseguros son entradas estáticas; nunca ejecutarlos.
