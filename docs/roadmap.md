# 🗺️ Roadmap - Security Advisor Auditor

Este documento describe el **plan de desarrollo futuro** del proyecto Security Advisor Auditor.

---

## 📊 Estado Actual

**Versión**: v2.2 (feature-complete) - 2026-11-08

**Fases completadas**: 1-5 del plan original ✅

**Tests**: 203 passed, 2 skipped ✅

---

## 🎯 Versión v2.3 (En Desarrollo)

**Fecha estimada**: 2026-11-09

**Estado**: En desarrollo activo

### ✅ Mejoras Ya Implementadas (v2.3)

| Módulo | Descripción | Fecha | Estado |
|--------|-------------|-------|--------|
| **M11** | Canal OOB para vulnerabilidades ciegas | 2026-11-08 | ✅ CI #73 verde |
| **M12** | SCA: SBOM + advisories (OSV) | 2026-11-08 | ✅ CI #75 verde |
| **M13** | Escaneo IaC y CI/CD | 2026-11-08 | ✅ CI #85 verde |
| **M14** | Detección diferencial IDOR/BOLA multi-sesión | 2026-11-09 | ✅ Implementado |
| **M15** | Exportación SARIF + Calculadora CVSS 3.1 | 2026-11-09 | ✅ Implementado |

### 📋 Detalles de Módulos v2.3

#### 🎯 M11 - Canal OOB (Out-of-Band) para Vulnerabilidades Ciegas

**Archivos**:
- `scripts/core/oob.py` - `OOBServer` HTTP en 127.0.0.1 puerto efímero
- `scripts/pentesting/oob_scanner.py` - `OOBScanner` con payloads ciegos

**Capacidades**:
- Detección de SSRF ciego
- Detección de XXE ciego
- Detección de RCE ciego
- Validación de scope/engagement
- Findings CONFIRMED con evidencias de interacción + callback

**CLI**:
```bash
python scripts/audit.py oob https://example.com --output ./results
```

**Tests**: `tests/test_oob.py` (E2E)

**Estado**: ✅ Implementado y probado

---

#### 📦 M12 - SCA: SBOM + Advisories

**Archivos**:
- `scripts/sca/sbom.py` - SBOM CycloneDX 1.5 determinista
- `scripts/sca/osv_client.py` - `OSVClient` (offline por defecto, online opt-in)
- `scripts/sca/scanner.py` - `SCAScanner`: advisory → finding CONFIRMED
- `scripts/sca/cli.py` - CLI propia

**Capacidades**:
- Generación de SBOM desde requirements.txt
- Cache versionada de advisories (advisories.json)
- Integración con OSV.dev (opcional, con validación de ScopeManager)
- Mapeo de advisories a findings con severidad, CWE y fix sugerido

**CLI**:
```bash
# Generar SBOM
python scripts/audit.py sca generate-sbom --requirements requirements.txt --output sbom.json

# Escanear vulnerabilidades (offline)
python scripts/audit.py sca scan --sbom sbom.json --output vulnerabilities.json

# Escanear con modo online
python scripts/audit.py sca scan --sbom sbom.json --online --output vulnerabilities.json
```

**Tests**: `tests/test_sca.py` con fixtures en `tests/fixtures/sca/`

**Desviaciones documentadas**:
- Priorización por AIEngine diferida
- CLI propia en vez de subcomando de audit.py

**Estado**: ✅ Implementado y probado

---

#### ☁️ M13 - Escaneo IaC y CI/CD

**Archivos**:
- `scripts/static_analysis/iac_analyzer.py` - `IaCAnalyzer` con `RuleEngine` compartido

**Familias soportadas**:
- **Dockerfile**: DOCK001-004
  - DOCK001: Usar imagen base oficial
  - DOCK002: Evitar RUN como root
  - DOCK003: Usar versión específica de imagen
  - DOCK004: Evitar secretos en Dockerfile

- **Kubernetes**: K8S001-004
  - K8S001: Evitar contenedores con privilegios
  - K8S002: Usar políticas de seguridad
  - K8S003: runAsNonRoot ausente (check de archivo)
  - K8S004: Límites de recursos

- **Terraform**: TF001-003
  - TF001: Evitar secretos en código
  - TF002: Bucket sin cifrado (check de archivo)
  - TF003: Acceso público restringido

- **GitHub Actions**: GHA001-004
  - GHA001: Permisos mínimos
  - GHA002: Evitar secrets en logs
  - GHA003: Workflows pinneados
  - GHA004: Validación de inputs

**CLI**:
```bash
python scripts/audit.py iac scan /ruta/a/iac/ --output ./iac-report
```

**Tests**: `tests/test_iac_analyzer.py` (10 tests) con fixtures en `tests/fixtures/iac/` (5 archivos)

**Dogfooding**: Documentado en `docs/iac.md`

**Fixes de iteración**:
- TF003 con raw string de comillas simples (SyntaxError con comilla doble anidada)
- Fixture deployment.yaml completado con `privileged: true`

**Estado**: ✅ Implementado y probado

---

#### 🎯 M14 - Detección Diferencial IDOR/BOLA Multi-Sesión

**Archivos**:
- `scripts/pentesting/differential.py` - `DifferentialTester`

**Capacidades**:
- Comparación de respuestas entre sesiones
- Detección de divergencias de status code
- Detección de divergencias de longitud de contenido
- Detección de divergencias de estructura JSON
- Generación automática de Findings con evidencia

**CLI**:
```bash
python scripts/audit.py idor https://example.com \
  --session1 admin \
  --session2 user \
  --output ./results
```

**Tests**: `tests/test_differential.py`

**Estado**: ✅ Implementado

---

#### 📊 M15 - Exportación SARIF + Calculadora CVSS 3.1

**Archivos**:
- `scripts/core/cvss.py` - `CVSSCalculator` con soporte completo para CVSS v3.1
- `scripts/reporting/sarif.py` - `SarifExporter` con exportación a SARIF 2.1.0

**Capacidades**:
- Vectores predefinidos para vulnerabilidades comunes
- Cálculo de base/impact/exploitability scores
- Mapeo de severidad
- Inclusión de CWE/CVSS en propiedades

**CLI**:
```bash
# Calculadora CVSS
python scripts/audit.py cvss --vuln-type sqli --json

# Exportación SARIF
python scripts/audit.py report audit.json --output report.sarif.json --format sarif
```

**Tests**: `tests/test_cvss.py` y `tests/test_sarif.py`

**Estado**: ✅ Implementado

---

## 🚀 Plan de Desarrollo Futuro

### 📅 Corto Plazo (v2.3 - v2.4)

#### Módulo de Análisis Estático
- [ ] Análisis interprocedimental completo
- [ ] Soporte para más lenguajes (Java, C#, Go, Rust)
- [ ] Integración con SonarQube y CodeQL
- [ ] Análisis de dependencias transitivas
- [ ] Detección de vulnerabilidades en configuraciones (YAML, JSON, TOML)

#### Módulo de Pentesting
- [ ] Escaneo automatizado de APIs GraphQL
- [ ] Detección de WebSockets vulnerables
- [ ] Pruebas de autenticación (brute force, credential stuffing)
- [ ] Integración con Burp Suite API
- [ ] Soporte para pruebas de DoS controladas
- [ ] Generación automática de informes de pentest

#### Módulo de Bug Bounty
- [ ] Integración con más plataformas (Intigriti, YesWeHack, etc.)
- [ ] Sistema de notificaciones automáticas
- [ ] Dashboard de métricas de programas
- [ ] Generación de reportes para plataformas externas
- [ ] Seguimiento de recompensas y pagos

#### Módulo de Reporting
- [ ] Generación de reportes en PDF
- [ ] Plantillas personalizables por cliente
- [ ] Exportación a sistemas de ticketing (Jira, GitHub Issues)
- [ ] Comparación de informes entre versiones
- [ ] Métricas de mejora de seguridad

---

### 📅 Medio Plazo (v2.4 - v2.5)

#### CLI y UX
- [ ] Interfaz web opcional (Flask/Dash)
- [ ] Modo interactivo con preguntas guiadas
- [ ] Autocompletado de comandos
- [ ] Validación automática de dependencias
- [ ] Configuración persistente

#### Infraestructura
- [ ] Soporte para Docker y contenedores
- [ ] Integración CI/CD avanzada (GitHub Actions, GitLab CI)
- [ ] Despliegue como servicio (opcional)
- [ ] Base de datos para historial de auditorías
- [ ] API REST para integración con otras herramientas

#### Seguridad
- [ ] Sandbox para ejecución segura de pruebas
- [ ] Sistema de cuotas y límites de uso
- [ ] Autenticación y autorización para API
- [ ] Cifrado de datos sensibles
- [ ] Auditoría de acciones

---

### 📅 Largo Plazo (v2.5+)

#### Análisis Avanzado
- [ ] Análisis semántico completo
- [ ] Detección de patrones de ataque avanzados
- [ ] Predicción de vulnerabilidades basadas en ML
- [ ] Análisis de comportamiento en tiempo real
- [ ] Correlación de eventos de seguridad

#### Integraciones
- [ ] Integración con SIEMs (Splunk, ELK, etc.)
- [ ] Integración con firewalls y WAFs
- [ ] Integración con sistemas de monitoring
- [ ] Integración con herramientas de DevSecOps

#### Automatización
- [ ] Automatización completa de auditorías
- [ ] Detección automática de cambios
- [ ] Respuesta automática a incidentes
- [ ] Remediación automática (opcional)

---

## 🎯 Prioridades por Impacto

### 🔴 Prioridad Crítica (v2.3)
1. **Exportación SARIF** - Para integración con herramientas de seguridad
2. **Calculadora CVSS 3.1** - Para estandarización de severidad
3. **SCA con SBOM** - Para análisis de dependencias
4. **Escaneo IaC** - Para seguridad en infraestructura
5. **Canal OOB** - Para detección de vulnerabilidades ciegas

### 🟡 Prioridad Alta (v2.3 - v2.4)
1. Análisis interprocedimental
2. Soporte para Java/C#/Go
3. Integración con Burp Suite
4. Dashboard web
5. Reportes en PDF

### 🟢 Prioridad Media (v2.4+)
1. Interfaz web completa
2. API REST
3. Base de datos para historial
4. Automatización CI/CD
5. Integración con SIEMs

---

## 📊 Métricas de Progreso

| Versión | Fecha | Tests | Módulos | Estado |
|---------|-------|-------|---------|--------|
| v2.0 | 2026-10-10 | 24 passed | 1 | ✅ Entregada |
| v2.0.1 | 2026-10-10 | 36 passed | 1 | ✅ Entregada |
| v2.1 | 2026-10-11 | 60 passed | 5 | ✅ Entregada |
| v2.1.1 | 2026-11-02 | 156 passed | 5 | ✅ Entregada |
| v2.2 | 2026-11-08 | 203 passed | 8 | ✅ Feature-Complete |
| v2.3 | 2026-11-09 | 203+ passed | 13+ | 🚧 En Desarrollo |

---

## 🤝 ¿Cómo Contribuir?

Si quieres contribuir al desarrollo de alguna de estas funcionalidades:

1. **Revisa las issues abiertas** en [GitHub Issues](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/issues)
2. **Crea una issue** para proponer una nueva funcionalidad
3. **Fork el repositorio** y crea un Pull Request
4. **Sigue las guías** en [CONTRIBUTING.md](../.github/CONTRIBUTING.md)

### Areas de Contribución

- **Nuevas Vulnerabilidades**: Añadir payloads a las wordlists en `scripts/pentesting/wordlists/`
- **Nuevas Plataformas**: Extender `scripts/bugbounty/platforms.py` con más integraciones
- **Nuevos Analizadores**: Añadir soporte para más lenguajes en `scripts/static_analysis/`
- **Mejoras de Rendimiento**: Optimizar el parser AST y el análisis de flujo
- **Documentación**: Mejorar guías y ejemplos en `docs/`
- **Tests**: Añadir más casos de prueba
- **UI/UX**: Mejorar mensajes de error y ayuda del CLI

---

## 📅 Calendario Estimado

| Versión | Fecha Estimada | Enfoque |
|---------|----------------|---------|
| v2.3 | Noviembre 2026 | SCA, IaC, OOB, SARIF, CVSS |
| v2.4 | Diciembre 2026 | Interprocedimental, Java/C#, Burp Suite |
| v2.5 | Enero 2027 | Dashboard web, API REST, Base de datos |

---

## 🎓 Recursos

- [Documentación de Arquitectura](architecture.md)
- [Metodología de Auditoría](../references/audit-methodology.md)
- [Guía de Contribución](../.github/CONTRIBUTING.md)
- [Changelog](history/changelog.md)

---

**Última actualización**: 2026-11-09

**Versión del documento**: 1.0
