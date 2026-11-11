# 📚 Security Advisor Auditor - Documentación

Bienvenido a la documentación oficial de **Security Advisor Auditor v2.2**.

---

## 🗂️ Estructura de la Documentación

```
docs/
├── README.md                    # 📍 Este archivo (índice)
├── architecture.md              # 🏗️ Arquitectura general del sistema
├── coverage.md                  # 📊 Cobertura de análisis estático
├── evaluation.md                # 📈 Evaluación y métricas
├── iac.md                       # ☁️ Análisis de IaC (Docker, K8s, Terraform)
├── pentesting.md                # 🔍 Guía del módulo de pentesting
├── bugbounty.md                 # 🐞 Guía del módulo de Bug Bounty
├── corrections-2.0.1.md        # 📝 Correcciones y ajustes
├── delivery.md                  # 📦 Entregas y verificaciones
├── implementation-plan.md       # 🎯 Plan de implementación
└── intelligence-plan.md         # 🧠 Plan de inteligencia
```

---

## 📖 Guía de Lectura

### 🎯 **Nuevos Usuarios: Por dónde empezar**

1. **[Arquitectura](architecture.md)** - Entender el diseño del sistema
2. **[Metodología de Auditoría](../references/audit-methodology.md)** - 21 fases completas
3. **[Pentesting](pentesting.md)** - Módulo de escaneo activo
4. **[Bug Bounty](bugbounty.md)** - Gestión de programas de recompensas

### 🛠️ **Desarrolladores: Documentación Técnica**

1. **[Arquitectura](architecture.md)** - Diseño y componentes
2. **[Cobertura](coverage.md)** - Detalles de análisis estático
3. **[Evaluación](evaluation.md)** - Métricas y resultados
4. **[IaC](iac.md)** - Análisis de infraestructura como código

### 📊 **Contribuidores: Información de Desarrollo**

1. **[Plan de Implementación](implementation-plan.md)** - Diseño y decisiones
2. **[Plan de Inteligencia](intelligence-plan.md)** - Diagnóstico inicial
3. **[Entregas](delivery.md)** - Historial de entregas
4. **[Correcciones](corrections-2.0.1.md)** - Ajustes y fixes

---

## 📁 Documentación por Módulo

### 🔍 **Análisis Estático**
- **Arquitectura**: [architecture.md](architecture.md)
- **Cobertura**: [coverage.md](coverage.md)
- **Metodología**: [../references/audit-methodology.md](../references/audit-methodology.md)

### 🎯 **Pentesting Activo**
- **Guía completa**: [pentesting.md](pentesting.md)
- **Escaneo**: ActiveScanner, detección de tecnologías, headers de seguridad
- **Fuzzing**: Pruebas de parámetros con wordlists
- **Explotación**: Ejecución controlada con permisos explícitos
- **PoC Generator**: Generación automática de Proof of Concept
- **Nuclei**: Integración con plantillas de vulnerabilidades

### 🐞 **Bug Bounty**
- **Guía completa**: [bugbounty.md](bugbounty.md)
- **Gestión de programas**: HackerOne, Bugcrowd, Intigriti, YesWeHack
- **Gestión de findings**: Registro, priorización, estadísticas
- **Priorización**: Sistema inteligente basado en múltiples factores

### 📦 **SCA (Software Composition Analysis)**
- **SBOM**: Generación de CycloneDX 1.5
- **Advisories**: Integración con OSV (offline/online)
- **Escaneo**: Detección de vulnerabilidades en dependencias

### ☁️ **IaC (Infraestructura como Código)**
- **Guía**: [iac.md](iac.md)
- **Soporte**: Docker, Kubernetes, Terraform, GitHub Actions
- **Reglas**: DOCK001-004, K8S001-004, TF001-003, GHA001-004

### 🤖 **IA y Automatización**
- **Deduplicación**: Automática de hallazgos idénticos
- **Priorización**: P0-P4 con justificación auditable
- **Ponderación**: Endpoints sensibles (/login, /admin, /api/auth)

---

## 📋 Referencias Externas

### Metodologías y Estándares
- **[Audit Methodology](../references/audit-methodology.md)** - 21 fases de auditoría
- **[Ethical Security](../references/ethical-security.md)** - Cumplimiento ético
- **[Evidence Policy](../references/evidence-policy.md)** - Políticas de evidencia
- **[Reporting Standard](../references/reporting-standard.md)** - Estándar de reportes
- **[Knowledge Index](../references/knowledge-index.md)** - Índice de conocimiento
- **[Platform Compatibility](../references/platform-compatibility.md)** - Compatibilidad con agentes

### Schemas
- **[Audit Report Schema](../schemas/audit-report.schema.json)** - Esquema de reportes
- **[Finding Schema](../schemas/finding.schema.json)** - Esquema de hallazgos

---

## 🎓 Recursos Adicionales

### Tutoriales y Ejemplos
- **[Examples](../examples/README.md)** - Ejemplos prácticos
- **[Safe Examples](../examples/safe/)** - Código seguro
- **[Vulnerable Examples](../examples/vulnerable/)** - Código con vulnerabilidades

### Desarrollo
- **[Changelog](history/changelog.md)** - Historial de versiones
- **[CONTRIBUTING](../.github/CONTRIBUTING.md)** - Guía para contribuidores
- **[CODE OF CONDUCT](../.github/CODE_OF_CONDUCT.md)** - Código de conducta

---

## 🔍 Búsqueda

Puedes buscar en toda la documentación usando:

```bash
# Buscar en todos los archivos markdown
grep -r "término" docs/ --include="*.md"

# Buscar con ripgrep (rg)
rg "término" docs/
```

---

## 📝 Convenciones

- **📌**: Información importante
- **✅**: Completado/Disponible
- **🚧**: En desarrollo
- **📋**: Lista/Tabla
- **🔗**: Enlace externo

---

**¿Necesitas ayuda?** Consulta [CONTRIBUTING.md](../.github/CONTRIBUTING.md) o abre un [Issue](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/issues).
