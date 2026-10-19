# Security Advisor Auditor v3.0 — Análisis de Seguridad Profesional

**Herramienta completa de auditoría de seguridad: Análisis estático + Pentesting + Bug Bounty**

Skill especializada para auditar **cualquier software** con evidencias y
remediación incremental. **v3.0 añade capacidades profesionales de pentesting y gestión de Bug Bounty.**

Preserva íntegramente las **21 fases** originales para web, SaaS, APIs, backend, móviles,
escritorio, CLI, bibliotecas, automatizaciones, CI/CD e infraestructura. Licencia MIT.

---

## 🚀 ¿Qué hay de nuevo en v3.0?

### ✨ Nuevas Capacidades de Pentesting
- **Escaneo Activo**: Descubrimiento de endpoints, detección de tecnologías (CMS/WAF), comprobación de headers de seguridad
- **Fuzzing Avanzado**: Pruebas de parámetros con wordlists para SQLi, XSS, SSRF, RCE, LFI, IDOR, XXE
- **Explotación Controlada**: Ejecución segura de exploits con sistema de permisos explícitos
- **Generación de PoCs**: Creación automática de Proof of Concept en Python, Bash y curl
- **Integración con Nuclei**: Ejecución de plantillas de vulnerabilidades conocidas

### 🎯 Gestión de Bug Bounty
- **Gestión de Programas**: Creación y seguimiento de programas de Bug Bounty
- **Gestión de Findings**: Registro detallado de vulnerabilidades con severidad, impacto, CVSS
- **Priorización Inteligente**: Sistema de puntuación basado en severidad, impacto, explotabilidad, scope y confianza
- **Integración con Plataformas**: HackerOne, Bugcrowd, Intigriti, YesWeHack

### 📊 Reportes Profesionales
- **Generación Multi-formato**: Markdown, HTML, JSON
- **Reportes Ejecutivos**: Resúmenes con estadísticas y métricas
- **Documentación de Evidencias**: Inclusión de PoCs y pasos de reproducción
- **Personalización**: Plantillas, filtros por severidad/tipo, redacción de secretos

---

## 📋 Capacidades Implementadas

### Análisis Estático (Heredado de v2.1)
- Skill Agent Skills con referencias progresivas y seis guías por dominio
- Inventario de lenguajes, manifests, frameworks y posibles superficies de ataque
- AST Python: contexto, propagación y llamadas locales acotadas
- Heurísticas de credenciales embebidas y HTML dinámico JS/TS
- ID, CWE, archivo/líneas, commit, fase, tipo, confianza, severidad justificada
- Informes Markdown/JSON y prompt de remediación

### Pentesting Activo (Nuevo en v3.0)

Combina la revisión contextual del agente con un helper local de **triaje estático**.
QUICK conserva candidatos sintácticos. STANDARD/DEEP añaden contexto Python,
trazas y estados conservadores; pueden tener falsos positivos y omisiones.
Cero coincidencias no demuestra seguridad. La revisión conserva arquitectura,
auth/authz, tenancy, lógica de negocio, concurrencia, privacidad y asesoría.

### Pentesting Activo (Nuevo en v3.0)
- **ActiveScanner**: Descubrimiento de endpoints, detección de tecnologías (CMS/WAF), comprobación de headers de seguridad
- **Fuzzer**: Pruebas de parámetros con payloads para SQLi, XSS, SSRF, RCE, LFI, IDOR, XXE, Command Injection
- **ExploitManager**: Ejecución controlada de exploits con validación de permisos
- **PoCGenerator**: Generación automática de Proof of Concept en múltiples lenguajes
- **NucleiIntegration**: Ejecución de plantillas de vulnerabilidades conocidas
- **AuthManager**: Gestión de sesiones autenticadas (cookies, bearer tokens, basic auth, OAuth2)

### Gestión de Bug Bounty (Nuevo en v3.0)
- **BugBountyManager**: Gestión completa de programas y findings
- **FindingPrioritizer**: Sistema de priorización basado en múltiples factores
- **Plataform Integrations**: HackerOne, Bugcrowd, Intigriti, YesWeHack

### Reportes (Mejorado en v3.0)
- **ProfessionalReporter**: Generación de reportes profesionales en Markdown, HTML, JSON
- Plantillas personalizables y filtros avanzados
- Redacción automática de secretos

---

## 🏗️ Arquitectura

```text
security-advisor-auditor/
├── SKILL.md, README.md, LICENSE, CHANGELOG.md
├── agents/openai.yaml
├── assets/icon.svg
├── references/                 # Metodología, políticas, fuentes y compatibilidad
├── modules/*.md                # Guías enfocadas; no motores ficticios
├── adapters/profiles.json      # Diferencias de rutas
├── schemas/audit-report.schema.json
├── scripts/
│   ├── audit.py                # CLI principal (estático + activo)
│   ├── security_auditor/       # Motor de análisis estático (heredado)
│   ├── pentesting/             # Módulos de pentesting (NUEVO)
│   │   ├── __init__.py
│   │   ├── auth.py             # Gestión de autenticación
│   │   ├── scanner.py          # Escaneo activo
│   │   ├── fuzzer.py           # Fuzzing de parámetros
│   │   ├── exploit.py          # Explotación controlada
│   │   ├── poc_generator.py    # Generación de PoCs
│   │   ├── nuclei_integration.py # Integración con Nuclei
│   │   └── wordlists/          # Wordlists para fuzzing
│   ├── bugbounty/              # Gestión de Bug Bounty (NUEVO)
│   │   ├── __init__.py
│   │   ├── manager.py          # Gestión de programas y findings
│   │   ├── platforms.py        # Integraciones con plataformas
│   │   └── prioritizer.py      # Priorización de findings
│   └── reporting/              # Reportes avanzados (NUEVO)
│       ├── __init__.py
│       └── advanced.py         # Generación de reportes profesionales
├── tests/                      # Tests unitarios
│   ├── test_pentesting.py     # Tests para módulo pentesting
│   ├── test_bugbounty.py      # Tests para módulo bugbounty
│   └── test_reporting.py      # Tests para módulo reporting
├── docs/                       # Documentación
│   ├── architecture.md
│   ├── coverage.md
│   ├── pentesting.md          # Documentación de pentesting (NUEVO)
│   └── bugbounty.md           # Documentación de bug bounty (NUEVO)
├── .github/workflows/          # CI/CD
│   ├── security-audit.yml
│   ├── pentesting.yml         # Workflow de pentesting (NUEVO)
│   └── bugbounty.yml           # Workflow de bug bounty (NUEVO)
└── install.py
```

---

## 📖 Documentación

- [Arquitectura y Diseño](docs/architecture.md) - Arquitectura general del sistema
- [Cobertura de Análisis](docs/coverage.md) - Detalles de cobertura de análisis estático
- [Módulo de Pentesting](docs/pentesting.md) - Guía completa del módulo de pentesting
- [Módulo de Bug Bounty](docs/bugbounty.md) - Guía completa del módulo de Bug Bounty

---

## 🛠️ Requisitos

### Requisitos Básicos (Heredados de v2.1)
Revisión manual: agente con acceso de lectura al objetivo. Helpers/instalador:
Python **3.10+**, biblioteca estándar. En Windows usar `python` o `py -3`;
Linux/macOS puede requerir `python3`. Git es opcional para HEAD.

### Requisitos Adicionales para v3.0

#### Dependencias Python (requirements.txt)
```
requests>=2.31.0
pyyaml>=6.0
beautifulsoup4>=4.12.0
jinja2>=3.1.0
markdown>=3.4.0
```

#### Herramientas Externas (Opcionales)
- **Nuclei**: Para escaneo de vulnerabilidades conocido
- **FFuF**: Para fuzzing de directorios
- **Gobuster**: Para descubrimiento de directorios
- **Burp Suite**: Para análisis manual (integración futura)
- **Metasploit**: Para explotación avanzada (integración futura)

---

## 🚀 Instalación

### Instalación Básica

```bash
# Clonar el repositorio
git clone https://github.com/bitacoradigitalia-coder/security-advisor-auditor.git
cd security-advisor-auditor

# Instalar dependencias
pip install -r requirements.txt
```

### Instalación de Herramientas Externas (Opcional)

```bash
# Nuclei (recomendado)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# FFuF
go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest

# Gobuster
go install github.com/OJ/gobuster/v3@latest
```

---

## 🎯 Uso

### CLI Principal

El comando principal es `python scripts/audit.py`. Consulta la ayuda completa:

```bash
python scripts/audit.py --help
```

### Comandos Disponibles

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `scan` | Análisis completo (estático + activo) | `python scripts/audit.py scan https://example.com --output ./report --active` |
| `fuzz` | Fuzzing de parámetros | `python scripts/audit.py fuzz https://example.com/api --param id --output ./fuzz-results` |
| `exploit` | Explotación controlada | `python scripts/audit.py exploit https://example.com/api?id=1 --vuln sqli --permission-file permissions.json` |
| `bugbounty` | Gestión de Bug Bounty | `python scripts/audit.py bugbounty add-program --name "Example Inc"` |
| `auth` | Gestión de autenticación | `python scripts/audit.py auth add-session --name admin --cookie session_id=12345` |
| `poc` | Generación de PoCs | `python scripts/audit.py poc generate --finding audit.json --output ./poc.py` |
| `report` | Generación de reportes | `python scripts/audit.py report audit.json --output ./final-report --format html` |
| `tools` | Herramientas disponibles | `python scripts/audit.py tools` |
| `validate-skill` | Validación de skill | `python scripts/audit.py validate-skill .` |

---

### Ejemplos de Uso

#### 1. Análisis Estático (Heredado de v2.1)

```bash
# Análisis rápido
python scripts/audit.py scan /ruta/repo --output ./informe --mode QUICK

# Análisis profundo
python scripts/audit.py scan /ruta/repo --output ./informe-deep --mode DEEP

# Con límites personalizados
python scripts/audit.py scan /ruta/repo --output ./informe --mode DEEP \
  --max-file-bytes 500000 --max-files 2000 --max-total-bytes 5000000
```

#### 2. Escaneo Activo (Nuevo en v3.0)

```bash
# Escaneo activo básico
python scripts/audit.py scan https://example.com --output ./report --active

# Escaneo con autenticación
python scripts/audit.py scan https://example.com --output ./report --active --session admin

# Escaneo con Nuclei
python scripts/audit.py scan https://example.com --output ./report --active --nuclei

# Escaneo con plantillas específicas de Nuclei
python scripts/audit.py scan https://example.com --output ./report --active --nuclei --nuclei-templates sqli,xss

# Escaneo completo con todas las opciones
python scripts/audit.py scan https://example.com --output ./report --active \
  --nuclei --fuzz --scan-js --scan-forms --scan-headers --scan-cookies
```

#### 3. Fuzzing de Parámetros

```bash
# Fuzzing básico
python scripts/audit.py fuzz https://example.com/api --param id --output ./fuzz-results

# Fuzzing con múltiples parámetros
python scripts/audit.py fuzz https://example.com/api --param id --param user --param token --output ./fuzz-results

# Fuzzing con wordlist personalizada
python scripts/audit.py fuzz https://example.com/api --param id --wordlist custom.txt --output ./fuzz-results

# Fuzzing con configuración avanzada
python scripts/audit.py fuzz https://example.com/api --param id --output ./fuzz-results \
  --threads 10 --timeout 30 --delay 0.5
```

#### 4. Explotación Controlada

```bash
# Explotación de SQLi (requiere archivo de permisos)
python scripts/audit.py exploit https://example.com/api?id=1 --vuln sqli \
  --permission-file permissions.json --output ./exploits

# Explotación de XSS
python scripts/audit.py exploit https://example.com/search?q=test --vuln xss \
  --permission-file permissions.json

# Crear archivo de permisos
python scripts/audit.py exploit --create-permission --target https://example.com --vuln-type sqli --output permissions.json
```

#### 5. Gestión de Autenticación

```bash
# Añadir sesión con cookies
python scripts/audit.py auth add-session --name admin --cookie session_id=12345 --cookie auth_token=xyz

# Añadir sesión con bearer token
python scripts/audit.py auth add-session --name api_user --auth-type bearer --token abc123

# Añadir sesión con autenticación básica
python scripts/audit.py auth add-session --name basic_user --auth-type basic --username user --password pass

# Listar sesiones
python scripts/audit.py auth list-sessions

# Eliminar sesión
python scripts/audit.py auth remove-session --name admin
```

#### 6. Gestión de Bug Bounty

```bash
# Añadir programa
python scripts/audit.py bugbounty add-program --name "Example Inc" \
  --scope example.com,api.example.com --platform hackerone

# Listar programas
python scripts/audit.py bugbounty list-programs

# Añadir finding a un programa
python scripts/audit.py bugbounty add-finding --program "Example Inc" \
  --title "SQL Injection in API" --severity critical --vuln-type sqli \
  --target https://api.example.com/users --description "SQLi vulnerability"

# Listar findings de un programa
python scripts/audit.py bugbounty list-findings --program "Example Inc"

# Priorizar findings
python scripts/audit.py bugbounty prioritize --program "Example Inc" --output prioritized.json

# Estadísticas de programa
python scripts/audit.py bugbounty stats --program "Example Inc"
```

#### 7. Generación de PoCs

```bash
# Generar PoC desde un finding
python scripts/audit.py poc generate --finding audit.json --language python --output ./poc.py

# Generar PoC en Bash
python scripts/audit.py poc generate --finding audit.json --language bash --output ./poc.sh

# Generar PoC en curl
python scripts/audit.py poc generate --finding audit.json --language curl --output ./poc_curl.sh
```

#### 8. Generación de Reportes

```bash
# Reporte en Markdown
python scripts/audit.py report audit.json --output ./report --format markdown

# Reporte en HTML
python scripts/audit.py report audit.json --output ./report --format html

# Reporte en JSON
python scripts/audit.py report audit.json --output ./report --format json

# Reporte con filtros
python scripts/audit.py report audit.json --output ./report --format html \
  --severity-filter critical,high --type-filter vulnerability

# Reporte con plantilla personalizada
python scripts/audit.py report audit.json --output ./report --format markdown \
  --template-path custom_template.md
```

---

## 🔒 Seguridad y Cumplimiento Ético

### Sistema de Permisos

**v3.0 implementa un sistema estricto de permisos para explotación:**

1. **Permiso Explicito Requerido**: La explotación de vulnerabilidades requiere un archivo de permisos válido
2. **Validación de Scope**: Los targets deben estar dentro del scope definido
3. **Rate Limiting**: Límite de 10 requests/segundo por defecto (configurable)
4. **User Agent Rotation**: Rotación de user agents para evitar detección

### Archivo de Permisos

Ejemplo de `permissions.json`:

```json
{
  "https://example.com": {
    "target": "https://example.com",
    "vulnerability_types": ["SQLi", "XSS", "RCE"],
    "allowed": true,
    "expires": "2024-12-31",
    "scope": "*.example.com",
    "notes": "Permission granted for authorized testing",
    "created": "2024-01-01 10:00:00"
  }
}
```

### Crear Archivo de Permisos

```bash
python scripts/audit.py exploit --create-permission \
  --target https://example.com \
  --vuln-type sqli,xss,rce \
  --expires 2024-12-31 \
  --scope "*.example.com" \
  --notes "Authorized testing permission" \
  --output permissions.json
```

### Buenas Prácticas

1. **Siempre obtener permiso escrito** antes de realizar pruebas de explotación
2. **Definir scope claramente** y no excederlo
3. **Usar rate limiting** para evitar DoS
4. **No realizar pruebas en producción** sin autorización explícita
5. **Documentar todas las acciones** para auditoría

---

## 📊 Ejecución de Tests

```bash
# Ejecutar todos los tests
python -B -m unittest discover -s tests -v

# Ejecutar tests específicos
python -B -m unittest tests.test_pentesting -v
python -B -m unittest tests.test_bugbounty -v
python -B -m unittest tests.test_reporting -v

# Ejecutar con cobertura
pip install pytest-cov
pytest tests/ --cov=scripts --cov-report=html
```

---

## 🔧 Configuración

### Configuración de Nuclei

Si Nuclei no está en el PATH, puedes especificar la ruta:

```bash
# Configurar ruta de Nuclei
python scripts/audit.py scan https://example.com --output ./report --active --nuclei-path /usr/local/bin/nuclei

# Usar plantillas personalizadas
python scripts/audit.py scan https://example.com --output ./report --active --nuclei-templates-path /path/to/templates
```

### Configuración de Wordlists

Las wordlists por defecto están en `scripts/pentesting/wordlists/`:
- `sqli.txt` - Payloads de SQL Injection
- `xss.txt` - Payloads de XSS
- `paths.txt` - Paths comunes
- `fuzzing.txt` - Valores para fuzzing
- `common_apis.txt` - Endpoints de API comunes

Puedes añadir tus propias wordlists y referenciarlas:

```bash
python scripts/audit.py fuzz https://example.com/api --param id --wordlist /path/to/custom_wordlist.txt --output ./results
```

### Configuración de Almacenamiento

Por defecto, los datos se guardan en:
- Sesiones de autenticación: `.security_advisor/auth_sessions.json`
- Permisos de explotación: `.security_advisor/permissions.json`
- Datos de Bug Bounty: `.security_advisor/bugbounty.json`

Puedes cambiar la ubicación:

```bash
# Configurar directorio de almacenamiento
python scripts/audit.py scan https://example.com --output ./report --storage-path /custom/path
```

---

## 📈 CI/CD

### Workflows de GitHub Actions

El proyecto incluye tres workflows principales:

1. **security-audit.yml**: Análisis de seguridad automático
2. **pentesting.yml**: Ejecución de pruebas de pentesting
3. **bugbounty.yml**: Gestión de Bug Bounty

### Ejecutar Workflows Manualmente

```bash
# Trigger workflow de pentesting
gh workflow run pentesting.yml --repo bitacoradigitalia-coder/security-advisor-auditor

# Trigger workflow de bug bounty
gh workflow run bugbounty.yml --repo bitacoradigitalia-coder/security-advisor-auditor
```

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor sigue estos pasos:

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/nueva-caracteristica`)
3. Añade tests para tu código
4. Ejecuta todos los tests (`python -B -m unittest discover -s tests -v`)
5. Crea un Pull Request

### Guías de Contribución

- **Nuevas Vulnerabilidades**: Añade payloads a las wordlists correspondientes
- **Nuevas Plataformas**: Extiende `scripts/bugbounty/platforms.py`
- **Nuevos Tipos de Reportes**: Extiende `scripts/reporting/advanced.py`
- **Mejoras de Rendimiento**: Optimiza el código existente

---

## 📜 Licencia

MIT License - Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- A la comunidad de seguridad por su continuo apoyo
- A los mantenedores de Nuclei y otras herramientas de código abierto
- A todos los contribuyentes que han hecho posible este proyecto

---

## 📞 Soporte

Para reportar bugs o solicitar características:

1. **Issues**: [GitHub Issues](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/issues)
2. **Discusiones**: [GitHub Discussions](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/discussions)
3. **Pull Requests**: [GitHub Pull Requests](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/pulls)

---

**Security Advisor Auditor v3.0 - Análisis de Seguridad Profesional para Hackers y Desarrolladores Senior** 🚀

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


## Profundidad y límites v2.1

```text
python scripts/audit.py scan /ruta/repo --output /ruta/informe --mode STANDARD
python scripts/audit.py scan /ruta/repo --output /ruta/informe-deep --mode DEEP --max-seconds 30 --max-memory-bytes 128000000 --max-findings 1000 --max-depth 32
python scripts/audit.py scan /ruta/repo --output /ruta/informe-legacy --mode STANDARD --legacy-report
python -B tests/evaluate_precision.py --output /ruta/evaluacion-nueva.json
python -B -m unittest discover -s tests -v
```

QUICK es el predeterminado para conservar el flujo anterior. STANDARD usa AST,
propagación intraprocedimental y modelos de consultas Flask. DEEP añade funciones
locales directas sin decoradores/variádicos, con profundidad limitada. No es
análisis interprocedimental completo. El parser corre en subproceso confiable
con límite de tiempo y memoria: Job Object en Windows, RLIMIT_AS en POSIX.
Si no puede imponer el límite, omite el archivo e informa del motivo.
Esto limita recursos del parser; no es un sandbox para ejecutar el objetivo.
También hay límites de archivos, bytes, nodos AST, profundidad y hallazgos.
El inventario tiene plazo cooperativo; lectura local y Git tienen límites separados.

`schema_version` sigue siendo 2.0 con extensiones opcionales. Consumidores
estrictos del esquema antiguo deben actualizarlo o usar `--legacy-report`.
Los IDs son deterministas por ubicación/regla/función y no cambian al añadir
hallazgos en otros archivos; desplazar líneas sí cambia la identidad.

Los estados y ejemplos se explican en [docs/architecture.md](docs/architecture.md),
[docs/coverage.md](docs/coverage.md) y [docs/evaluation.md](docs/evaluation.md).
La precisión del conjunto sintético no representa la precisión general.
