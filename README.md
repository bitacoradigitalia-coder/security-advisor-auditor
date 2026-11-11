# Security Advisor Auditor

**Herramienta profesional de auditoría de seguridad**: Análisis estático + Pentesting + Bug Bounty + SCA + IaC

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 203 passed, 2 skipped](https://img.shields.io/badge/tests-203%20passed%2C%202%20skipped-green.svg)](#)
[![Code Style: PEP 8](https://img.shields.io/badge/code%20style-PEP%208-blue.svg)](https://peps.python.org/pep-0008/)
[![Maintenance: Yes](https://img.shields.io/badge/maintenance-yes-green.svg)](#)
[![Open Source: Yes](https://img.shields.io/badge/open%20source-yes-brightgreen.svg)](#)
[![Contributions: Welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)](.github/CONTRIBUTING.md)

---

## 📌 About

**Security Advisor Auditor** es una herramienta completa de auditoría de seguridad para **cualquier tipo de software**: aplicaciones web, SaaS, APIs, backend, móviles, CLI, bibliotecas, automatizaciones, CI/CD e infraestructura.

- **Versión actual**: v2.2 (feature-complete: Fases 1-5 completadas)
- **Licencia**: MIT
- **Requisitos**: Python 3.10+, biblioteca estándar
- **Tests**: 203 passed, 2 skipped

---

## ✨ Módulos Implementados

| Módulo | Descripción | Estado |
|--------|-------------|--------|
| **Análisis Estático** | AST Python, JS, TS, PHP con motor de reglas compartido | ✅ v2.1-2.2 |
| **Pentesting** | Scanner activo, Fuzzer, Exploits controlados, PoC Generator | ✅ v2.2 |
| **Bug Bounty** | Gestión de programas y findings con priorización inteligente | ✅ v2.2 |
| **Reporting** | Markdown, HTML, JSON, SARIF 2.1.0 con CVSS 3.1 | ✅ v2.2-2.3 |
| **SCA** | SBOM (CycloneDX 1.5), Advisories (OSV), dependencias auditadas | ✅ v2.3 |
| **IaC** | Análisis de Docker, Kubernetes, Terraform, GitHub Actions | ✅ v2.3 |
| **IA** | Deduplicación automática, priorización P0-P4, ponderación de endpoints sensibles | ✅ v2.2 |

---

## 🚀 Instalación

### Requisitos
- Python **3.10+** (biblioteca estándar)
- Git (opcional, para HEAD)

### Dependencias Python
```bash
pip install -r requirements.txt
```

**Dependencias**: `requests`, `pyyaml`, `beautifulsoup4`, `jinja2`, `markdown`

### Herramientas Externas (Opcionales)
- **Nuclei**: Escaneo de vulnerabilidades conocidas
- **FFuF / Gobuster**: Descubrimiento de directorios
- **Burp Suite / Metasploit**: Análisis manual (integración futura)

```bash
# Nuclei (recomendado)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# FFuF
go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest

# Gobuster
go install github.com/OJ/gobuster/v3@latest
```

---

## 💻 Uso Rápido

El CLI principal es `python scripts/audit.py`:

```bash
# Ver ayuda completa
python scripts/audit.py --help

# Ver herramientas disponibles
python scripts/audit.py tools

# Validar skill
python scripts/audit.py validate-skill .
```

### Análisis Estático
```bash
# Análisis rápido (modo por defecto)
python scripts/audit.py scan /ruta/repo --output ./informe

# Análisis profundo
python scripts/audit.py scan /ruta/repo --output ./informe --mode DEEP

# Con límites personalizados
python scripts/audit.py scan /ruta/repo --output ./informe \
  --max-file-bytes 500000 --max-files 2000 --max-total-bytes 5000000
```

### Escaneo Activo (requiere permisos explícitos)
```bash
# Escaneo básico
python scripts/audit.py scan https://example.com --output ./report --active

# Con Nuclei
python scripts/audit.py scan https://example.com --output ./report --active --nuclei

# Con autenticación
python scripts/audit.py scan https://example.com --output ./report --active --session admin

# Completo con todas las opciones
python scripts/audit.py scan https://example.com --output ./report --active \
  --nuclei --fuzz --scan-js --scan-forms --scan-headers --scan-cookies
```

### Fuzzing
```bash
# Fuzzing básico de parámetros
python scripts/audit.py fuzz https://example.com/api --param id --output ./results

# Con múltiples parámetros
python scripts/audit.py fuzz https://example.com/api --param id --param user --output ./results

# Con wordlist personalizada
python scripts/audit.py fuzz https://example.com/api --param id --wordlist custom.txt --output ./results
```

### Explotación Controlada
```bash
# Requiere archivo de permisos válido
python scripts/audit.py exploit https://example.com/api?id=1 --vuln sqli \
  --permission-file permissions.json --output ./exploits

# Crear archivo de permisos
python scripts/audit.py exploit --create-permission \
  --target https://example.com --vuln-type sqli,xss,rce \
  --expires 2024-12-31 --output permissions.json
```

### Gestión de Autenticación
```bash
# Añadir sesión con cookies
python scripts/audit.py auth add-session --name admin --cookie session_id=12345

# Añadir sesión con bearer token
python scripts/audit.py auth add-session --name api_user --auth-type bearer --token abc123

# Listar sesiones
python scripts/audit.py auth list-sessions
```

### Gestión de Bug Bounty
```bash
# Añadir programa
python scripts/audit.py bugbounty add-program --name "Example Inc" \
  --scope example.com,api.example.com --platform hackerone

# Añadir finding
python scripts/audit.py bugbounty add-finding --program "Example Inc" \
  --title "SQL Injection in API" --severity critical --vuln-type sqli \
  --target https://api.example.com/users

# Priorizar findings
python scripts/audit.py bugbounty prioritize --program "Example Inc" --output prioritized.json
```

### Generación de PoCs
```bash
# Generar PoC en Python
python scripts/audit.py poc generate --finding audit.json --language python --output ./poc.py

# Generar PoC en Bash
python scripts/audit.py poc generate --finding audit.json --language bash --output ./poc.sh

# Generar PoC en curl
python scripts/audit.py poc generate --finding audit.json --language curl --output ./poc_curl.sh
```

### Generación de Reportes
```bash
# Reporte en Markdown
python scripts/audit.py report audit.json --output ./report --format markdown

# Reporte en HTML
python scripts/audit.py report audit.json --output ./report --format html

# Reporte en JSON
python scripts/audit.py report audit.json --output ./report --format json

# Reporte en SARIF 2.1.0
python scripts/audit.py report audit.json --output ./report --format sarif

# Con filtros
python scripts/audit.py report audit.json --output ./report --format html \
  --severity-filter critical,high --type-filter vulnerability
```

### SCA (Software Composition Analysis)
**Nota:** El módulo SCA tiene su propio CLI independiente (no integrado en audit.py).

```bash
# Generar SBOM (CycloneDX 1.5)
python scripts/sca/cli.py --requirements requirements.txt --output ./sca-report

# Escanear vulnerabilidades (offline con cache)
python scripts/sca/cli.py --requirements requirements.txt --output ./sca-report

# Escanear con modo online (opt-in)
python scripts/sca/cli.py --requirements requirements.txt --output ./sca-report --online
```

### Escaneo IaC
**Nota:** El módulo IaC tiene su propio analizador (no integrado en audit.py).

```bash
# Analizar archivos de infraestructura (usar el analizador directamente)
python -c "from scripts.static_analysis.iac_analyzer import IaCAnalyzer; IaCAnalyzer().analyze_directory('/ruta/iac/')"
```

---

## 🔒 Seguridad y Cumplimiento Ético

### Sistema de Permisos (v2.2)
La explotación de vulnerabilidades **requiere permiso explícito**:

1. **Permiso explícito requerido**: Archivo de permisos válido
2. **Validación de scope**: Targets deben estar dentro del scope definido
3. **Rate limiting**: 10 requests/segundo por defecto (configurable)
4. **User Agent Rotation**: Para evitar detección

### Archivo de Permisos (permissions.json)
```json
{
  "https://example.com": {
    "target": "https://example.com",
    "vulnerability_types": ["SQLi", "XSS", "RCE"],
    "allowed": true,
    "expires": "2024-12-31",
    "scope": "*.example.com",
    "notes": "Permission granted for authorized testing"
  }
}
```

### Buenas Prácticas
1. ✅ **Siempre obtener permiso escrito** antes de pruebas de explotación
2. ✅ **Definir scope claramente** y no excederlo
3. ✅ **Usar rate limiting** para evitar DoS
4. ✅ **No realizar pruebas en producción** sin autorización explícita
5. ✅ **Documentar todas las acciones** para auditoría

---

## 📚 Documentación

### Metodología y Arquitectura
- [🏗️ Arquitectura](docs/architecture.md) - Diseño general del sistema
- [📋 Metodología de Auditoría](references/audit-methodology.md) - 21 fases completas
- [🔒 Políticas de Seguridad](references/ethical-security.md) - Cumplimiento ético
- [📊 Cobertura de Análisis](docs/coverage.md) - Detalles de cobertura

### Módulos
- [🐞 Bug Bounty](docs/bugbounty.md) - Gestión completa de programas
- [🔍 Pentesting](docs/pentesting.md) - Guía del módulo de pentesting
- [📦 SCA](docs/sca.md) - Análisis de composiciones de software
- [☁️ IaC](docs/iac.md) - Análisis de infraestructura como código

### Desarrollo
- [📜 Historial de Versiones](docs/history/changelog.md) - Todas las versiones y cambios
- [🎯 Roadmap](docs/roadmap.md) - Plan de desarrollo futuro
- [⚙️ Instalación para Agentes](install.py) - Instalador multi-agente

---

## 🧪 Tests

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

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor sigue:

1. **Fork** el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/nueva-caracteristica`)
3. Añade **tests** para tu código
4. Ejecuta **todos los tests** (`python -B -m unittest discover -s tests -v`)
5. Crea un **Pull Request**

**Requisitos para PRs:**
- ✅ Todos los tests pasan
- ✅ Código limpio y bien documentado
- ✅ Sigue el estilo del proyecto
- ✅ Incluye actualización de CHANGELOG si aplica

Ver [CONTRIBUTING.md](.github/CONTRIBUTING.md) para más detalles.

---

## 📜 Licencia

MIT License - Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- A la comunidad de seguridad por su continuo apoyo
- A los mantenedores de Nuclei y otras herramientas de código abierto
- A todos los contribuyentes que han hecho posible este proyecto

---

## 🆘 Soporte

- **Issues**: [GitHub Issues](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/issues)
- **Discusiones**: [GitHub Discussions](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/discussions)
- **Pull Requests**: [GitHub Pull Requests](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/pulls)

---

**Security Advisor Auditor v2.2 - Análisis de Seguridad Profesional para Hackers y Desarrolladores Senior** 🚀
