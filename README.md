# Security Advisor Auditor

**Herramienta profesional de auditoría de seguridad**: Análisis estático + Pentesting + Bug Bounty + SCA + IaC

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI Tests](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/actions/workflows/ci-tests.yml/badge.svg)](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/actions/workflows/ci-tests.yml)
[![Code Style: PEP 8](https://img.shields.io/badge/code%20style-PEP%208-blue.svg)](https://peps.python.org/pep-0008/)
[![Maintenance: Yes](https://img.shields.io/badge/maintenance-yes-green.svg)](#)
[![Open Source: Yes](https://img.shields.io/badge/open%20source-yes-brightgreen.svg)](#)
[![Contributions: Welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)](.github/CONTRIBUTING.md)

---

## 📌 About

**Security Advisor Auditor** es una herramienta completa de auditoría de seguridad para **cualquier tipo de software**: aplicaciones web, SaaS, APIs, backend, móviles, CLI, bibliotecas, automatizaciones, CI/CD e infraestructura.

- **Versión actual**: v2.2 (feature-complete: Fases 1-5 completadas)
- **Licencia**: MIT
- **Requisitos**: Python 3.10+ y dependencias de `requirements.txt`
- **Tests**: consulta [la CI del commit](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/actions/workflows/ci-tests.yml)

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
- Python **3.10+**
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

El CLI principal es `python scripts/audit.py`. Desde la raíz del proyecto:

```bash
python scripts/audit.py --help
python scripts/audit.py scan /ruta/repositorio --output ./informe
python scripts/audit.py scan /ruta/repositorio --output ./informe-profundo --mode DEEP
python scripts/audit.py extract-zip programa.zip --output ./extraido
python scripts/audit.py scan ./extraido --output ./informe-zip
```

Usa un directorio nuevo para cada informe, fuera de la carpeta analizada. El escaneo estático lee código sin ejecutar el programa. No es un antivirus de ejecutables ni garantiza que un repositorio sea seguro.

**Estado de la aplicación:** actualmente se utiliza por CLI. El dashboard, el botón para seleccionar archivos o repositorios, las integraciones Hermes/WAF y la monetización siguen pendientes. No hay una implementación de detección zero-day acreditada en este checkout.

El comando `scan` usa el motor de `scripts/security_auditor/`. Los analizadores de `scripts/static_analysis/` y SCA se utilizan de forma independiente; tener esos módulos en el repositorio no implica que `scan` los ejecute.

```bash
python scripts/sca/cli.py --requirements requirements.txt --output ./sca-report
python -c "import json; from scripts.static_analysis.iac_analyzer import IaCAnalyzer; print(json.dumps(IaCAnalyzer().analyze_directory('/ruta/iac').to_dict(), indent=2))"
```

Consulta la [guía de uso](docs/usage.md) para alcance autorizado, sesiones, pruebas activas, SCA, IaC y reportes. La [referencia CLI](docs/cli.md) enumera los argumentos implementados.

---

## 🔒 Seguridad y Cumplimiento Ético

### Sistema de Permisos (v2.2)
La explotación de vulnerabilidades **requiere permiso explícito**:

1. **Permiso explícito requerido**: Archivo de permisos válido
2. **Validación de scope**: Targets deben estar dentro del scope definido
3. **Rate limiting**: 10 requests/segundo por defecto (configurable)
4. **User Agent Rotation**: Para evitar detección

### Configuración del alcance y permisos

Consulta la [guía de uso](docs/usage.md#alcance-de-pruebas-activas) para configurar destinos permitidos. `exploit` exige un archivo de permisos válido; el formato se define en [el módulo de explotación](scripts/pentesting/exploit.py). No existe una opción CLI `--create-permission`.

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
- [📦 SCA](docs/usage.md#sca) - Análisis de composiciones de software
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
