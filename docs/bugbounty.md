# Security Advisor Auditor v3.0 - Módulo de Bug Bounty

**Documentación completa del módulo de gestión de Bug Bounty para hunters profesionales**

---

## 📖 Introducción

El módulo de **Bug Bounty** de Security Advisor Auditor v3.0 proporciona un sistema completo para la gestión profesional de programas de Bug Bounty. Este módulo permite gestionar programas, findings, priorización, integración con plataformas y generación de reportes.

**Características principales:**
- ✅ Gestión de programas de Bug Bounty
- ✅ Gestión detallada de findings
- ✅ Sistema de priorización inteligente
- ✅ Integración con plataformas (HackerOne, Bugcrowd, Intigriti, YesWeHack)
- ✅ Generación de reportes profesionales
- ✅ Estadísticas y métricas
- ✅ Validación de scope

---

## 🏗️ Arquitectura

```
scripts/bugbounty/
├── __init__.py              # Exports del módulo
├── manager.py               # Gestión de programas y findings (BugBountyManager)
├── platforms.py             # Integraciones con plataformas
├── prioritizer.py           # Priorización de findings (FindingPrioritizer)
└── docs/                    # Documentación (este archivo)
```

---

## 📚 Conceptos Clave

### Bug Bounty Program
Un **programa de Bug Bounty** representa una iniciativa de una organización para recompensar la identificación de vulnerabilidades de seguridad. Incluye:
- Nombre y descripción
- Scope (dominios/IPs en scope)
- Reglas y políticas
- Plataforma (HackerOne, Bugcrowd, etc.)
- Recompensas
- Vulnerabilidades elegibles e inelegibles

### Bug Bounty Finding
Un **finding** representa una vulnerabilidad identificada en un programa. Incluye:
- Título y descripción
- Severidad y impacto
- Tipo de vulnerabilidad
- Target (URL/endpoint)
- Pasos para reproducir
- Proof of Concept
- Recomendaciones
- Estado (nuevo, triado, cerrado, etc.)
- Confianza
- Recompensa

### Priorización
El sistema de **priorización** asigna una puntuación a cada finding basado en:
- Severidad (35%)
- Impacto (25%)
- Explotabilidad (20%)
- Scope (10%)
- Confianza (10%)

---

## 🚀 Configuración

### Requisitos

- Python 3.10+
- Dependencias: `requests`
- API tokens para plataformas (opcional)

### Instalación

```bash
# Instalar dependencias
pip install -r requirements.txt
```

### Configuración de API Tokens

Para integrar con plataformas de Bug Bounty, necesitas API tokens:

```bash
# HackerOne
python scripts/audit.py bugbounty configure-platform --platform hackerone --api-token YOUR_TOKEN

# Bugcrowd
python scripts/audit.py bugbounty configure-platform --platform bugcrowd --api-token YOUR_TOKEN

# Intigriti
python scripts/audit.py bugbounty configure-platform --platform intigriti --api-token YOUR_TOKEN
```

---

## 🎯 Gestión de Programas

### Descripción

El `BugBountyManager` permite gestionar programas de Bug Bounty, incluyendo creación, actualización, eliminación y listado.

### Uso

#### CLI

```bash
# Añadir programa
python scripts/audit.py bugbounty add-program \
  --name "Example Inc" \
  --scope example.com,api.example.com \
  --platform hackerone \
  --platform-handle example \
  --severity-system CVSS \
  --reward-range-min 100 \
  --reward-range-max 10000 \
  --in-scope-assets api.example.com,web.example.com \
  --out-of-scope-assets staging.example.com \
  --eligible-vulnerabilities SQLi,XSS,RCE,IDOR \
  --ineligible-vulnerabilities DoS,Spam

# Añadir programa (mínimo)
python scripts/audit.py bugbounty add-program \
  --name "Simple Program" \
  --scope example.com

# Listar programas
python scripts/audit.py bugbounty list-programs

# Obtener información de un programa
python scripts/audit.py bugbounty get-program --name "Example Inc"

# Actualizar programa
python scripts/audit.py bugbounty update-program \
  --name "Example Inc" \
  --scope example.com,api.example.com,new.example.com \
  --active false

# Eliminar programa
python scripts/audit.py bugbounty remove-program --name "Example Inc"

# Estadísticas de un programa
python scripts/audit.py bugbounty stats --name "Example Inc"
```

#### Python API

```python
from scripts.bugbounty.manager import BugBountyManager, BugBountyProgram

# Crear BugBountyManager
manager = BugBountyManager(storage_path=".security_advisor/bugbounty.json")

# Añadir programa
program = manager.add_program(
    name="Example Inc",
    scope=["example.com", "api.example.com"],
    rules="No DoS attacks, no automated scanning without permission",
    platform="hackerone",
    platform_handle="example",
    api_token="your_api_token",
    severity_system="CVSS",
    reward_range={"min": 100, "max": 10000},
    in_scope_assets=["api.example.com", "web.example.com"],
    out_of_scope_assets=["staging.example.com"],
    eligible_vulnerabilities=["SQLi", "XSS", "RCE", "IDOR", "SSRF"],
    ineligible_vulnerabilities=["DoS", "Spam", "Clickjacking"],
    active=True,
    notes="Production program"
)

# Listar programas
programs = manager.list_programs()
print(f"Programs: {programs}")

# Obtener programa
program = manager.get_program("Example Inc")
print(f"Program: {program.name}")

# Actualizar programa
updated = manager.update_program(
    name="Example Inc",
    scope=["example.com", "api.example.com", "new.example.com"],
    active=False
)

# Eliminar programa
removed = manager.remove_program("Example Inc")
print(f"Removed: {removed}")

# Obtener estadísticas
def stats = manager.get_program_statistics("Example Inc")
print(f"Statistics: {stats}")
```

### Ejemplo de Programa

```python
program = BugBountyProgram(
    name="Example Inc Bug Bounty",
    scope=["*.example.com"],
    rules="""
    - No Denial of Service attacks
    - No automated scanning without permission
    - Report vulnerabilities within 24 hours
    - One report per vulnerability
    - No testing on production without explicit permission
    """,
    platform="hackerone",
    platform_handle="example",
    api_token="hk1_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    severity_system="CVSS",
    reward_range={"min": 50, "max": 5000},
    in_scope_assets=[
        "api.example.com",
        "web.example.com",
        "mobile.example.com"
    ],
    out_of_scope_assets=[
        "staging.example.com",
        "dev.example.com",
        "internal.example.com"
    ],
    eligible_vulnerabilities=[
        "SQL Injection",
        "Cross-Site Scripting",
        "Remote Code Execution",
        "Server-Side Request Forgery",
        "Insecure Direct Object Reference",
        "XML External Entity",
        "Command Injection",
        "Path Traversal",
        "Authentication Bypass",
        "Privilege Escalation"
    ],
    ineligible_vulnerabilities=[
        "Denial of Service",
        "Spam",
        "Clickjacking",
        "Content Spoofing",
        "Email Spoofing",
        "Rate Limiting",
        "Missing Security Headers",
        "Information Disclosure (non-sensitive)"
    ],
    active=True,
    notes="Production bug bounty program"
)
```

---

## 🔍 Gestión de Findings

### Descripción

El `BugBountyManager` permite gestionar findings (vulnerabilidades identificadas) para cada programa.

### Uso

#### CLI

```bash
# Añadir finding
python scripts/audit.py bugbounty add-finding \
  --program "Example Inc" \
  --title "SQL Injection in User API" \
  --description "SQL injection vulnerability in the user endpoint" \
  --target "https://api.example.com/users" \
  --severity critical \
  --impact data_breach \
  --vuln-type sqli \
  --cvss-score 9.8 \
  --cvss-vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" \
  --steps-to-reproduce "1. Send GET request with payload: id=' OR '1'='1" \
  --proof-of-concept "' OR '1'='1" \
  --impact-description "Full database access including user credentials" \
  --remediation "Use parameterized queries instead of string concatenation" \
  --confidence high \
  --tags sqli,api,critical,database

# Añadir finding desde archivo de scan
python scripts/audit.py bugbounty add-finding \
  --program "Example Inc" \
  --file ./scan-results/audit.json

# Listar findings de un programa
python scripts/audit.py bugbounty list-findings --program "Example Inc"

# Obtener información de un finding
python scripts/audit.py bugbounty get-finding --program "Example Inc" --finding-id FINDING_ID

# Actualizar finding
python scripts/audit.py bugbounty update-finding \
  --program "Example Inc" \
  --finding-id FINDING_ID \
  --severity critical \
  --status triaged

# Eliminar finding
python scripts/audit.py bugbounty remove-finding --program "Example Inc" --finding-id FINDING_ID

# Buscar findings
python scripts/audit.py bugbounty search-findings --program "Example Inc" --severity critical
```

#### Python API

```python
from scripts.bugbounty.manager import BugBountyManager, BugBountyFinding

# Crear BugBountyManager
manager = BugBountyManager()

# Añadir finding
finding = manager.add_finding(
    title="SQL Injection in User API",
    program_name="Example Inc",
    description="SQL injection vulnerability in the user endpoint",
    target="https://api.example.com/users",
    severity="critical",
    impact="data_breach",
    vulnerability_type="SQLi",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    steps_to_reproduce=[
        "1. Send GET request to /users with parameter id=' OR '1'='1",
        "2. Observe database error in response"
    ],
    proof_of_concept="' OR '1'='1",
    impact_description="Full database access including user credentials",
    remediation="Use parameterized queries instead of string concatenation",
    status="new",
    confidence="high",
    reward=5000,
    is_duplicate=False,
    is_submitted=False,
    submission_date=None,
    submission_id=None,
    tags=["sqli", "api", "critical", "database"]
)

# Listar findings
findings = manager.list_findings("Example Inc")
print(f"Findings: {len(findings)}")

# Obtener finding
finding = manager.get_finding("Example Inc", finding.id)
print(f"Finding: {finding.title}")

# Actualizar finding
updated = manager.update_finding(
    program_name="Example Inc",
    finding_id=finding.id,
    severity="critical",
    status="triaged",
    reward=5000
)

# Eliminar finding
removed = manager.remove_finding("Example Inc", finding.id)
print(f"Removed: {removed}")

# Listar todos los findings
all_findings = manager.list_all_findings()
print(f"All findings: {len(all_findings)}")
```

### Ejemplo de Finding

```python
finding = BugBountyFinding(
    title="Stored XSS in User Profile",
    program_name="Example Inc",
    description="""
    Stored Cross-Site Scripting vulnerability in the user profile page.
    Attackers can inject malicious JavaScript that will be executed
    when other users view the profile.
    """,
    target="https://example.com/profile",
    severity="high",
    impact="account_compromise",
    vulnerability_type="XSS",
    cvss_score=8.2,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
    steps_to_reproduce=[
        "1. Navigate to user profile page",
        "2. In the 'About Me' field, enter: <script>alert(document.cookie)</script>",
        "3. Save the profile",
        "4. View another user's profile or your own",
        "5. Observe JavaScript execution"
    ],
    proof_of_concept="<script>alert(document.cookie)</script>",
    impact_description="""
    Attackers can steal user session cookies, perform actions on behalf of users,
    and potentially take over user accounts. Can affect all users who view
    the compromised profile.
    """,
    remediation="""
    Implement proper output encoding/escaping for all user-supplied data.
    Use Content Security Policy (CSP) headers to restrict inline script execution.
    Sanitize HTML input using a library like DOMPurify.
    """,
    status="new",
    confidence="confirmed",
    reward=3000,
    is_duplicate=False,
    is_submitted=False,
    submission_date=None,
    submission_id=None,
    tags=["xss", "stored", "high", "account-takeover"]
)
```

---

## ⚡ Priorización de Findings

### Descripción

El `FindingPrioritizer` asigna una puntuación a cada finding basado en múltiples factores, permitiendo enfocarse en las vulnerabilidades más críticas.

### Sistema de Puntuación

La puntuación total se calcula como:

```
Total Score = (Severity × 0.35) + (Impact × 0.25) + (Exploitability × 0.20) + (Scope × 0.10) + (Confidence × 0.10)
```

### Puntuaciones por Factor

#### Severity (35%)

| Nivel | Puntuación |
|-------|------------|
| Critical | 10.0 |
| High | 7.0 |
| Medium | 5.0 |
| Low | 2.5 |
| Info | 0.5 |

#### Impact (25%)

| Tipo de Impacto | Puntuación |
|----------------|------------|
| data_breach | 10.0 |
| rce | 9.5 |
| privilege_escalation | 9.0 |
| auth_bypass | 8.5 |
| data_manipulation | 8.0 |
| dos | 7.5 |
| xss | 7.0 |
| information_disclosure | 6.5 |
| csrf | 6.0 |
| sqli | 8.5 |
| ssrf | 7.5 |
| lfi | 7.0 |
| rfi | 7.5 |
| idor | 7.0 |
| xxe | 7.0 |
| command_injection | 9.0 |
| path_traversal | 6.5 |
| open_redirect | 5.0 |
| misconfiguration | 5.0 |

#### Exploitability (20%)

| Nivel | Puntuación |
|-------|------------|
| remote | 10.0 |
| network | 8.0 |
| local | 7.0 |
| physical | 3.0 |

#### Scope (10%)

| Entorno | Puntuación |
|---------|------------|
| production | 10.0 |
| staging | 7.0 |
| development | 3.0 |

#### Confidence (10%)

| Nivel | Puntuación |
|-------|------------|
| confirmed | 10.0 |
| high | 8.0 |
| medium | 5.0 |
| low | 2.0 |

### Uso

#### CLI

```bash
# Priorizar findings de un programa
python scripts/audit.py bugbounty prioritize --program "Example Inc" --output prioritized.json

# Priorizar con pesos personalizados
python scripts/audit.py bugbounty prioritize --program "Example Inc" \
  --severity-weight 0.4 \
  --impact-weight 0.3 \
  --exploitability-weight 0.2 \
  --scope-weight 0.05 \
  --confidence-weight 0.05 \
  --output prioritized.json

# Obtener top N findings
python scripts/audit.py bugbounty prioritize --program "Example Inc" --top 10 --output top10.json
```

#### Python API

```python
from scripts.bugbounty.prioritizer import FindingPrioritizer, PriorityScore

# Crear FindingPrioritizer
prioritizer = FindingPrioritizer()

# Priorizar un finding
finding = {
    'id': '1',
    'title': 'SQL Injection',
    'severity': 'critical',
    'impact': 'data_breach',
    'exploitability': 'remote',
    'scope': 'production',
    'confidence': 'confirmed'
}

score = prioritizer.prioritize(finding)
print(f"Score: {score.score}")
print(f"Priority Level: {prioritizer.get_priority_level(score.score)}")

# Priorizar múltiples findings
findings = [
    {'id': '1', 'severity': 'critical', 'impact': 'data_breach', 'exploitability': 'remote', 'scope': 'production', 'confidence': 'confirmed'},
    {'id': '2', 'severity': 'high', 'impact': 'rce', 'exploitability': 'remote', 'scope': 'staging', 'confidence': 'high'},
    {'id': '3', 'severity': 'medium', 'impact': 'xss', 'exploitability': 'network', 'scope': 'development', 'confidence': 'medium'}
]

scores = prioritizer.prioritize_multiple(findings)

# Ordenar por puntuación
sorted_scores = sorted(scores, key=lambda x: x.score, reverse=True)

for score in sorted_scores:
    print(f"Finding {score.finding_id}: {score.score} ({prioritizer.get_priority_level(score.score)})")
```

### Niveles de Prioridad

| Puntuación | Nivel | Acción Recomendada |
|-----------|-------|---------------------|
| 8.0 - 10.0 | Critical | Reportar inmediatamente, parchear urgentemente |
| 6.0 - 7.9 | High | Reportar en 24-48 horas, parchear pronto |
| 4.0 - 5.9 | Medium | Reportar en 1 semana, parchear en próximo ciclo |
| 2.0 - 3.9 | Low | Reportar en 1 mes, parchear cuando sea posible |
| 0.0 - 1.9 | Info | Documentar, no requiere acción inmediata |

### Ejemplo de Priorización

```python
# Finding 1: Critical SQLi in production
finding1 = {
    'id': '1',
    'severity': 'critical',      # 10.0 × 0.35 = 3.5
    'impact': 'data_breach',     # 10.0 × 0.25 = 2.5
    'exploitability': 'remote',  # 10.0 × 0.20 = 2.0
    'scope': 'production',       # 10.0 × 0.10 = 1.0
    'confidence': 'confirmed'   # 10.0 × 0.10 = 1.0
}
# Total: 3.5 + 2.5 + 2.0 + 1.0 + 1.0 = 10.0 (Critical)

# Finding 2: High XSS in staging
finding2 = {
    'id': '2',
    'severity': 'high',         # 7.0 × 0.35 = 2.45
    'impact': 'xss',             # 7.0 × 0.25 = 1.75
    'exploitability': 'network', # 8.0 × 0.20 = 1.6
    'scope': 'staging',         # 7.0 × 0.10 = 0.7
    'confidence': 'high'        # 8.0 × 0.10 = 0.8
}
# Total: 2.45 + 1.75 + 1.6 + 0.7 + 0.8 = 7.3 (High)

# Finding 3: Medium misconfiguration in development
finding3 = {
    'id': '3',
    'severity': 'medium',       # 5.0 × 0.35 = 1.75
    'impact': 'misconfiguration', # 5.0 × 0.25 = 1.25
    'exploitability': 'local',  # 7.0 × 0.20 = 1.4
    'scope': 'development',     # 3.0 × 0.10 = 0.3
    'confidence': 'medium'     # 5.0 × 0.10 = 0.5
}
# Total: 1.75 + 1.25 + 1.4 + 0.3 + 0.5 = 5.2 (Medium)
```

---

## 🌐 Integración con Plataformas

### Descripción

El módulo incluye integraciones con las principales plataformas de Bug Bounty:
- **HackerOne**
- **Bugcrowd**
- **Intigriti**
- **YesWeHack**

### Uso

#### CLI

```bash
# Configurar API token para HackerOne
python scripts/audit.py bugbounty configure-platform \
  --platform hackerone \
  --api-token YOUR_HACKERONE_TOKEN

# Obtener información de usuario de HackerOne
python scripts/audit.py bugbounty get-user-info --platform hackerone

# Listar programas de HackerOne
python scripts/audit.py bugbounty list-platform-programs --platform hackerone

# Enviar reporte a HackerOne
python scripts/audit.py bugbounty submit-report \
  --platform hackerone \
  --program example \
  --finding-id FINDING_ID \
  --template hackerone

# Obtener estado de reporte
python scripts/audit.py bugbounty get-report-status \
  --platform hackerone \
  --report-id 12345
```

#### Python API

```python
from scripts.bugbounty.platforms import (
    HackerOneIntegration,
    BugcrowdIntegration,
    IntigritiIntegration,
    YesWeHackIntegration
)

# HackerOne
api_token = "hk1_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
hackerone = HackerOneIntegration(api_token=api_token)

# Obtener información de usuario
user_info = hackerone.get_user_info()
print(f"User: {user_info['data']['username']}")

# Listar programas
programs = hackerone.list_programs()
print(f"Programs: {len(programs['data'])}")

# Enviar reporte
report_data = {
    'title': 'SQL Injection in User API',
    'vulnerability_type': 'SQL Injection',
    'severity': 'critical',
    'description': 'SQL injection vulnerability...',
    'steps_to_reproduce': ['1. Send request with payload...'],
    'impact': 'Full database access',
    'remediation': 'Use parameterized queries'
}

report = hackerone.submit_report("example", report_data)
print(f"Report ID: {report['data']['id']}")

# Bugcrowd
bugcrowd_token = "bc_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
bugcrowd = BugcrowdIntegration(api_token=bugcrowd_token)

# Obtener información de usuario
user_info = bugcrowd.get_user_info()
print(f"User: {user_info['email']}")

# Listar programas
programs = bugcrowd.list_programs()
print(f"Programs: {len(programs)}")

# Intigriti
intigriti_token = "it_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
intigriti = IntigritiIntegration(api_token=intigriti_token)

# Obtener información de usuario
user_info = intigriti.get_user_info()
print(f"User: {user_info['username']}")
```

### Configuración de Plataformas

```python
from scripts.bugbounty.platforms import PLATFORMS, PlatformConfig

# Ver plataformas disponibles
print("Available platforms:")
for name, config in PLATFORMS.items():
    print(f"  - {name}: {config.base_url}")

# Configuración de HackerOne
hackerone_config = PLATFORMS['hackerone']
print(f"HackerOne API URL: {hackerone_config.api_url}")
```

### Enviar Reportes a Plataformas

```python
# Preparar datos del reporte
report_data = {
    'title': 'Stored XSS in User Profile',
    'vulnerability_type': 'Cross-Site Scripting',
    'severity': 'high',
    'cvss_score': 8.2,
    'description': 'Stored XSS vulnerability...',
    'steps_to_reproduce': [
        '1. Navigate to profile page',
        '2. Enter XSS payload in bio field',
        '3. Save profile',
        '4. View profile to trigger XSS'
    ],
    'impact': 'Account takeover possible',
    'remediation': 'Implement output encoding and CSP',
    'proof_of_concept': '<script>alert(document.cookie)</script>',
    'tags': ['xss', 'stored', 'high']
}

# Enviar a HackerOne
hackerone = HackerOneIntegration(api_token="hk1_XXXXXX")
report = hackerone.submit_report("example-program", report_data)
print(f"Report submitted with ID: {report['data']['id']}")
```

---

## 📊 Estadísticas y Métricas

### Descripción

El módulo proporciona estadísticas detalladas sobre programas y findings.

### Uso

#### CLI

```bash
# Estadísticas de un programa
python scripts/audit.py bugbounty stats --program "Example Inc"

# Estadísticas de todos los programas
python scripts/audit.py bugbounty stats-all

# Resumen ejecutivo
python scripts/audit.py bugbounty executive-summary --output summary.md
```

#### Python API

```python
from scripts.bugbounty.manager import BugBountyManager

# Crear manager
manager = BugBountyManager()

# Estadísticas de un programa
stats = manager.get_program_statistics("Example Inc")
print(f"Program Statistics:")
print(f"  Total Findings: {stats['total_findings']}")
print(f"  By Severity: {stats['by_severity']}")
print(f"  By Type: {stats['by_type']}")
print(f"  By Status: {stats['by_status']}")
print(f"  Average CVSS: {stats['average_cvss']}")
print(f"  Total Reward: ${stats['total_reward']}")

# Estadísticas de todos los programas
all_stats = manager.get_all_statistics()
print(f"All Programs Statistics:")
print(f"  Total Programs: {all_stats['total_programs']}")
print(f"  Total Findings: {all_stats['total_findings']}")
print(f"  By Platform: {all_stats['by_platform']}")
print(f"  Global Average CVSS: {all_stats['global_average_cvss']}")
```

### Ejemplo de Estadísticas

```json
{
  "program_name": "Example Inc",
  "total_findings": 42,
  "by_severity": {
    "critical": 5,
    "high": 12,
    "medium": 18,
    "low": 7,
    "info": 0
  },
  "by_type": {
    "SQLi": 8,
    "XSS": 15,
    "IDOR": 7,
    "SSRF": 3,
    "RCE": 2,
    "Misconfiguration": 7
  },
  "by_status": {
    "new": 10,
    "triaged": 15,
    "submitted": 12,
    "closed": 5,
    "duplicate": 0
  },
  "average_cvss": 7.2,
  "total_reward": 25000,
  "average_reward": 595.24,
  "most_common_vulnerability": "XSS",
  "highest_severity_count": 12
}
```

---

## 📄 Generación de Reportes

### Descripción

El módulo permite generar reportes profesionales para submission a plataformas de Bug Bounty.

### Uso

#### CLI

```bash
# Generar reporte Markdown
python scripts/audit.py report ./findings/audit.json --output ./reports --format markdown

# Generar reporte HTML
python scripts/audit.py report ./findings/audit.json --output ./reports --format html

# Generar reporte con plantilla de HackerOne
python scripts/audit.py report ./findings/audit.json --output ./reports \
  --format markdown --template hackerone

# Generar reporte para un finding específico
python scripts/audit.py bugbounty generate-report \
  --program "Example Inc" \
  --finding-id FINDING_ID \
  --output ./reports \
  --format markdown
```

#### Python API

```python
from scripts.bugbounty.manager import BugBountyManager
from scripts.reporting.advanced import ProfessionalReporter, ReportConfig

# Obtener findings
manager = BugBountyManager()
findings = manager.list_findings("Example Inc")

# Convertir findings a formato para reporte
report_findings = []
for finding in findings:
    report_findings.append({
        'id': finding.id,
        'title': finding.title,
        'severity': finding.severity,
        'type': 'vulnerability',
        'target': finding.target,
        'description': finding.description,
        'impact': finding.impact_description,
        'cvss_score': finding.cvss_score,
        'cvss_vector': finding.cvss_vector,
        'steps_to_reproduce': finding.steps_to_reproduce,
        'proof_of_concept': finding.proof_of_concept,
        'remediation': finding.remediation,
        'tags': finding.tags
    })

# Generar reporte
reporter = ProfessionalReporter()
config = ReportConfig(
    title=f"Security Audit Report - Example Inc",
    subtitle="Generated by Security Advisor Auditor v3.0",
    author="Security Researcher",
    company="Security Advisor",
    include_executive_summary=True,
    include_technical_details=True,
    include_recommendations=True,
    include_appendices=True,
    output_format="markdown",
    redact_secrets=True,
    include_cvss=True
)

report = reporter.generate_report(report_findings, config)

# Guardar reporte
with open("report.md", "w") as f:
    f.write(report)
```

### Plantillas de Reportes

El módulo incluye plantillas para diferentes plataformas:

#### Plantilla para HackerOne

```markdown
# [Title] - [Program Name]

## Vulnerability Type
[Type]

## Severity
[Critical/High/Medium/Low]

## CVSS Score
[Score] - [Vector]

## Description
[Description]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact
[Impact Description]

## Proof of Concept
```
[PoC Code]
```

## Remediation
[Remediation Steps]

## References
- [Reference 1]
- [Reference 2]
```

#### Plantilla para Bugcrowd

```markdown
# Summary
[Brief summary of the vulnerability]

# Description
[Detailed description]

# Steps to Reproduce
1. [Step 1]
2. [Step 2]

# Supporting Material/References
- [Evidence]
- [Screenshots]

# Impact
[Impact description]

# Remediation Guidance
[How to fix the vulnerability]
```

---

## 🔍 Validación de Scope

### Descripción

El módulo valida que los targets de los findings están dentro del scope definido para cada programa.

### Uso

#### CLI

```bash
# Validar scope de un target
python scripts/audit.py bugbounty check-scope \
  --program "Example Inc" \
  --target https://api.example.com

# Validar múltiples targets
python scripts/audit.py bugbounty check-scope \
  --program "Example Inc" \
  --targets https://api.example.com,https://web.example.com,https://other.com
```

#### Python API

```python
from scripts.bugbounty.manager import BugBountyManager

# Crear manager
manager = BugBountyManager()

# Añadir programa con scope
manager.add_program(
    name="Example Inc",
    scope=["*.example.com"],
    in_scope_assets=["api.example.com", "web.example.com"],
    out_of_scope_assets=["staging.example.com"]
)

# Validar targets
print(manager.check_scope("Example Inc", "https://api.example.com"))  # True
print(manager.check_scope("Example Inc", "https://web.example.com"))  # True
print(manager.check_scope("Example Inc", "https://staging.example.com"))  # False
print(manager.check_scope("Example Inc", "https://other.com"))  # False
```

### Patrones de Scope

El módulo soporta varios patrones de scope:

| Patrón | Ejemplo | Coincide con |
|--------|---------|--------------|
| Dominio exacto | `example.com` | `example.com` |
| Subdominio wildcard | `*.example.com` | `api.example.com`, `web.example.com` |
| Multi-nivel wildcard | `*.api.example.com` | `v1.api.example.com` |
| Path específico | `example.com/api` | `example.com/api`, `example.com/api/v1` |
| IP | `192.168.1.1` | `192.168.1.1` |
| Rango CIDR | `192.168.1.0/24` | `192.168.1.1` - `192.168.1.254` |

---

## 📊 Ejemplos Completos

### Ejemplo 1: Flujo Completo de Bug Bounty

```python
from scripts.bugbounty.manager import BugBountyManager, BugBountyProgram, BugBountyFinding
from scripts.bugbounty.prioritizer import FindingPrioritizer
from scripts.reporting.advanced import ProfessionalReporter, ReportConfig

# 1. Crear programa
manager = BugBountyManager()
program = manager.add_program(
    name="Example Inc",
    scope=["*.example.com"],
    platform="hackerone",
    platform_handle="example",
    reward_range={"min": 100, "max": 10000}
)

# 2. Añadir findings desde scan
finding1 = manager.add_finding(
    title="SQL Injection in User API",
    program_name="Example Inc",
    severity="critical",
    vulnerability_type="SQLi",
    target="https://api.example.com/users",
    description="SQL injection vulnerability...",
    cvss_score=9.8,
    impact="data_breach",
    confidence="confirmed"
)

finding2 = manager.add_finding(
    title="Stored XSS in Profile",
    program_name="Example Inc",
    severity="high",
    vulnerability_type="XSS",
    target="https://example.com/profile",
    description="Stored XSS vulnerability...",
    cvss_score=8.2,
    impact="account_compromise",
    confidence="confirmed"
)

# 3. Priorizar findings
prioritizer = FindingPrioritizer()
findings = manager.list_findings("Example Inc")

prioritized = []
for finding in findings:
    score = prioritizer.prioritize({
        'id': finding.id,
        'severity': finding.severity,
        'impact': finding.impact,
        'exploitability': 'remote',
        'scope': 'production',
        'confidence': finding.confidence
    })
    prioritized.append((finding, score))

# Ordenar por puntuación
prioritized.sort(key=lambda x: x[1].score, reverse=True)

print("Prioritized Findings:")
for finding, score in prioritized:
    print(f"  {finding.title}: {score.score} ({prioritizer.get_priority_level(score.score)})")

# 4. Generar reporte
reporter = ProfessionalReporter()
config = ReportConfig(
    title=f"Security Audit Report - Example Inc",
    output_format="markdown"
)

report_findings = []
for finding, _ in prioritized:
    report_findings.append({
        'id': finding.id,
        'title': finding.title,
        'severity': finding.severity,
        'type': 'vulnerability',
        'target': finding.target,
        'description': finding.description,
        'cvss_score': finding.cvss_score,
        'impact': finding.impact,
        'remediation': finding.remediation
    })

report = reporter.generate_report(report_findings, config)

# Guardar reporte
with open("report.md", "w") as f:
    f.write(report)

# 5. Marcar como enviado
for finding, _ in prioritized[:5]:  # Top 5 findings
    manager.update_finding(
        program_name="Example Inc",
        finding_id=finding.id,
        is_submitted=True,
        submission_date="2024-01-15",
        status="submitted"
    )
```

### Ejemplo 2: Integración con HackerOne

```python
from scripts.bugbounty.manager import BugBountyManager
from scripts.bugbounty.platforms import HackerOneIntegration

# 1. Configurar HackerOne
api_token = "hk1_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
hackerone = HackerOneIntegration(api_token=api_token)

# 2. Obtener información de usuario
user_info = hackerone.get_user_info()
print(f"Logged in as: {user_info['data']['username']}")

# 3. Listar programas disponibles
programs = hackerone.list_programs()
print(f"Available programs: {len(programs['data'])}")

# 4. Obtener findings locales
manager = BugBountyManager()
findings = manager.list_findings("Example Inc")

# 5. Enviar findings a HackerOne
for finding in findings[:5]:  # Enviar top 5
    report_data = {
        'title': finding.title,
        'vulnerability_type': finding.vulnerability_type,
        'severity': finding.severity,
        'cvss_score': finding.cvss_score,
        'description': finding.description,
        'steps_to_reproduce': finding.steps_to_reproduce,
        'impact': finding.impact_description,
        'remediation': finding.remediation,
        'proof_of_concept': finding.proof_of_concept
    }
    
    report = hackerone.submit_report("example", report_data)
    print(f"Submitted {finding.title} with ID: {report['data']['id']}")
    
    # Actualizar finding local
    manager.update_finding(
        program_name="Example Inc",
        finding_id=finding.id,
        is_submitted=True,
        submission_id=report['data']['id'],
        submission_date="2024-01-15",
        status="submitted"
    )

# 6. Obtener estado de los reportes
for finding in findings[:5]:
    if finding.submission_id:
        status = hackerone.get_report_status(finding.submission_id)
        print(f"Report {finding.submission_id} status: {status['data']['state']}")
```

### Ejemplo 3: Estadísticas y Métricas

```python
from scripts.bugbounty.manager import BugBountyManager

# Crear manager
manager = BugBountyManager()

# Añadir múltiples programas y findings
programs = ["Program A", "Program B", "Program C"]
for program_name in programs:
    manager.add_program(name=program_name, scope=[f"*.{program_name.lower()}.com"])
    
    # Añadir findings con diferentes severidades
    severities = ["critical", "high", "medium", "low"]
    for i, severity in enumerate(severities):
        manager.add_finding(
            title=f"{severity.title()} Finding {i+1}",
            program_name=program_name,
            severity=severity,
            vulnerability_type="SQLi",
            cvss_score=[9.8, 7.5, 5.0, 2.5][i],
            reward=[5000, 2000, 500, 100][i]
        )

# Obtener estadísticas globales
stats = manager.get_all_statistics()
print(f"Global Statistics:")
print(f"  Total Programs: {stats['total_programs']}")
print(f"  Total Findings: {stats['total_findings']}")
print(f"  By Platform: {stats['by_platform']}")
print(f"  Global Average CVSS: {stats['global_average_cvss']:.2f}")
print(f"  Total Reward: ${stats['total_reward']}")
print(f"  By Severity: {stats['by_severity']}")

# Estadísticas por programa
for program_name in programs:
    program_stats = manager.get_program_statistics(program_name)
    print(f"\n{program_name} Statistics:")
    print(f"  Total Findings: {program_stats['total_findings']}")
    print(f"  Average CVSS: {program_stats['average_cvss']:.2f}")
    print(f"  Total Reward: ${program_stats['total_reward']}")
    print(f"  Most Common Vulnerability: {program_stats['most_common_vulnerability']}")
```

---

## 🔒 Seguridad y Buenas Prácticas

### Validación de Scope

Siempre valida que los targets están dentro del scope:

```python
# Antes de añadir un finding
if not manager.check_scope(program_name, target):
    print(f"Warning: {target} is out of scope for {program_name}")
    # No añadir el finding o marcar como out of scope
```

### Manejo de Datos Sensibles

El módulo redacta automáticamente secretos en reportes:

```python
config = ReportConfig(
    redact_secrets=True,  # Habilitado por defecto
    output_format="markdown"
)
```

### Autenticación Segura

Usa autenticación para acceder a endpoints protegidos:

```python
from scripts.pentesting.auth import AuthManager

# Configurar sesión
auth_manager = AuthManager()
auth_manager.add_session(
    name="hackerone",
    auth_type="bearer",
    token="hk1_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    base_url="https://api.hackerone.com"
)
```

### Rate Limiting

Configura rate limiting para evitar detección:

```python
# En scanner
config = ScanConfig(
    delay_between_requests=1.0,
    max_requests_per_second=5
)

# En AuthManager
auth_manager.check_rate_limit("session", "https://api.example.com/endpoint")
```

---

## 📚 API Reference

### BugBountyManager

```python
class BugBountyManager:
    def __init__(self, storage_path: Optional[str] = None)
    
    # Gestión de programas
    def add_program(
        name: str,
        scope: List[str] = None,
        rules: str = "",
        platform: str = "generic",
        platform_handle: str = "",
        api_token: str = "",
        severity_system: str = "CVSS",
        reward_range: Dict[str, int] = None,
        in_scope_assets: List[str] = None,
        out_of_scope_assets: List[str] = None,
        eligible_vulnerabilities: List[str] = None,
        ineligible_vulnerabilities: List[str] = None,
        active: bool = True,
        notes: str = ""
    ) -> BugBountyProgram
    
    def get_program(self, name: str) -> Optional[BugBountyProgram]
    def list_programs(self) -> List[str]
    def update_program(self, name: str, **kwargs) -> BugBountyProgram
    def remove_program(self, name: str) -> bool
    
    # Gestión de findings
    def add_finding(
        title: str,
        program_name: str,
        description: str = "",
        target: str = "",
        severity: str = "medium",
        impact: str = "low",
        vulnerability_type: str = "other",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        steps_to_reproduce: List[str] = None,
        proof_of_concept: str = "",
        impact_description: str = "",
        remediation: str = "",
        status: str = "new",
        confidence: str = "medium",
        reward: int = 0,
        is_duplicate: bool = True,
        is_submitted: bool = False,
        submission_date: str = None,
        submission_id: str = None,
        tags: List[str] = None
    ) -> BugBountyFinding
    
    def get_finding(self, program_name: str, finding_id: str) -> Optional[BugBountyFinding]
    def list_findings(self, program_name: str) -> List[BugBountyFinding]
    def list_all_findings(self) -> List[BugBountyFinding]
    def update_finding(self, program_name: str, finding_id: str, **kwargs) -> BugBountyFinding
    def remove_finding(self, program_name: str, finding_id: str) -> bool
    
    # Validación de scope
    def check_scope(self, program_name: str, target: str) -> bool
    
    # Estadísticas
    def get_program_statistics(self, program_name: str) -> Dict[str, Any]
    def get_all_statistics(self) -> Dict[str, Any]
```

### BugBountyProgram

```python
@dataclass
class BugBountyProgram:
    name: str
    scope: List[str] = field(default_factory=list)
    rules: str = ""
    platform: str = "generic"
    platform_handle: str = ""
    api_token: str = ""
    severity_system: str = "CVSS"
    reward_range: Dict[str, int] = field(default_factory=dict)
    in_scope_assets: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    eligible_vulnerabilities: List[str] = field(default_factory=list)
    ineligible_vulnerabilities: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    active: bool = True
    notes: str = ""
    
    def is_in_scope(self, target: str) -> bool
    def to_dict(self) -> Dict[str, Any]
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BugBountyProgram'
```

### BugBountyFinding

```python
@dataclass
class BugBountyFinding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    program_name: str = ""
    description: str = ""
    target: str = ""
    severity: str = "medium"
    impact: str = "low"
    vulnerability_type: str = "other"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    impact_description: str = ""
    remediation: str = ""
    status: str = "new"
    confidence: str = "medium"
    reward: int = 0
    is_duplicate: bool = True
    is_submitted: bool = False
    submission_date: str = None
    submission_id: str = None
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BugBountyFinding'
```

### FindingPrioritizer

```python
class FindingPrioritizer:
    DEFAULT_WEIGHTS = {
        'severity': 0.35,
        'impact': 0.25,
        'exploitability': 0.20,
        'scope': 0.10,
        'confidence': 0.10
    }
    
    SEVERITY_SCORES = {...}
    IMPACT_SCORES = {...}
    EXPLOITABILITY_SCORES = {...}
    SCOPE_SCORES = {...}
    CONFIDENCE_SCORES = {...}
    
    def prioritize(self, finding: Dict[str, Any], weights: Optional[Dict[str, float]] = None) -> PriorityScore
    def prioritize_multiple(self, findings: List[Dict[str, Any]], weights: Optional[Dict[str, float]] = None) -> List[PriorityScore]
    def get_priority_level(self, score: float) -> str
    def sort_findings_by_priority(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]
```

### Plataform Integrations

```python
class HackerOneIntegration:
    def __init__(self, api_token: str)
    def get_user_info(self) -> Dict[str, Any]
    def list_programs(self) -> Dict[str, Any]
    def get_program(self, handle: str) -> Dict[str, Any]
    def submit_report(self, program_handle: str, report_data: Dict[str, Any]) -> Dict[str, Any]
    def get_report(self, report_id: str) -> Dict[str, Any]
    def get_report_status(self, report_id: str) -> Dict[str, Any]
    def update_report(self, report_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]
    def close_report(self, report_id: str) -> Dict[str, Any]

class BugcrowdIntegration:
    def __init__(self, api_token: str)
    def get_user_info(self) -> Dict[str, Any]
    def list_programs(self) -> List[Dict[str, Any]]
    def submit_report(self, program_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]

class IntigritiIntegration:
    def __init__(self, api_token: str)
    def get_user_info(self) -> Dict[str, Any]
    def list_programs(self) -> List[Dict[str, Any]]
    def submit_report(self, program_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]

class YesWeHackIntegration:
    def __init__(self, api_token: str)
    def get_user_info(self) -> Dict[str, Any]
    def list_programs(self) -> List[Dict[str, Any]]
    def submit_report(self, program_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]
```

---

## 🚀 Best Practices

### 1. Organización de Programas

```python
# Añadir programas con información completa
manager.add_program(
    name="Company Inc",
    scope=["*.company.com"],
    platform="hackerone",
    platform_handle="company",
    severity_system="CVSS",
    reward_range={"min": 100, "max": 10000},
    in_scope_assets=["api.company.com", "web.company.com"],
    out_of_scope_assets=["staging.company.com", "dev.company.com"],
    eligible_vulnerabilities=["SQLi", "XSS", "RCE", "IDOR", "SSRF"],
    ineligible_vulnerabilities=["DoS", "Spam", "Clickjacking"],
    active=True,
    notes="Production bug bounty program"
)
```

### 2. Documentación de Findings

```python
# Añadir findings con información detallada
finding = manager.add_finding(
    title="SQL Injection in User Registration",
    program_name="Company Inc",
    description="""
    SQL injection vulnerability in the user registration endpoint.
    The application concatenates user input directly into SQL queries
    without proper sanitization or parameterization.
    """,
    target="https://api.company.com/register",
    severity="critical",
    impact="data_breach",
    vulnerability_type="SQLi",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    steps_to_reproduce=[
        "1. Send POST request to /register with payload: username=' OR '1'='1&email=test@test.com&password=pass",
        "2. Observe database error in response",
        "3. Modify payload to extract data: username=' UNION SELECT username,password FROM users -- &email=test@test.com&password=pass"
    ],
    proof_of_concept="' OR '1'='1",
    impact_description="""
    Attackers can extract, modify, or delete data from the database.
    This includes user credentials, personal information, and other sensitive data.
    Full database compromise is possible.
    """,
    remediation="""
    1. Use parameterized queries (prepared statements) instead of string concatenation
    2. Implement input validation and sanitization
    3. Apply the principle of least privilege to database accounts
    4. Use ORM frameworks that handle SQL injection protection
    """,
    status="new",
    confidence="confirmed",
    reward=5000,
    tags=["sqli", "api", "critical", "database", "registration"]
)
```

### 3. Priorización Regular

```python
# Priorizar findings regularmente
prioritizer = FindingPrioritizer()
findings = manager.list_findings("Company Inc")

prioritized = prioritizer.prioritize_multiple(findings)
sorted_findings = prioritizer.sort_findings_by_priority(findings)

# Enfocarse en findings críticos
critical_findings = [f for f in sorted_findings if f['severity'] == 'critical']
```

### 4. Integración con Plataformas

```python
# Sincronizar con plataformas regularmente
hackerone = HackerOneIntegration(api_token="hk1_XXXXXX")

# Obtener programas de la plataforma
platform_programs = hackerone.list_programs()

# Sincronizar con programas locales
for platform_program in platform_programs['data']:
    if not manager.get_program(platform_program['handle']):
        manager.add_program(
            name=platform_program['name'],
            platform="hackerone",
            platform_handle=platform_program['handle']
        )
```

### 5. Generación de Reportes

```python
# Generar reportes profesionales regularmente
from scripts.reporting.advanced import ProfessionalReporter, ReportConfig

reporter = ProfessionalReporter()
config = ReportConfig(
    title="Monthly Security Report",
    author="Security Team",
    company="Security Advisor",
    include_executive_summary=True,
    include_technical_details=True,
    include_recommendations=True,
    output_format="markdown"
)

# Obtener findings del mes
findings = manager.list_findings("Company Inc")
monthly_findings = [f for f in findings if f.created_at.startswith("2024-01")]

# Generar reporte
report = reporter.generate_report(monthly_findings, config)

# Guardar reporte
with open("monthly_report.md", "w") as f:
    f.write(report)
```

---

## 🔍 Troubleshooting

### API Token Inválido

**Problema:** `Invalid API token`

**Solución:**
```bash
# Verificar token
python scripts/audit.py bugbounty test-connection --platform hackerone

# Actualizar token
python scripts/audit.py bugbounty configure-platform --platform hackerone --api-token NEW_TOKEN
```

### Programa no encontrado

**Problema:** `Program not found`

**Solución:**
```python
# Verificar que el programa existe
manager = BugBountyManager()
programs = manager.list_programs()
print(f"Available programs: {programs}")
```

### Finding fuera de scope

**Problema:** `Target is out of scope`

**Solución:**
```python
# Verificar scope del programa
program = manager.get_program("Company Inc")
print(f"Scope: {program.scope}")
print(f"In scope assets: {program.in_scope_assets}")
print(f"Out of scope assets: {program.out_of_scope_assets}")

# Validar target
is_in_scope = manager.check_scope("Company Inc", "https://api.company.com")
print(f"Is in scope: {is_in_scope}")
```

### Error de persistencia

**Problema:** `Error saving data`

**Solución:**
```bash
# Verificar permisos en el directorio
ls -la .security_advisor/

# Cambiar permisos
chmod 700 .security_advisor/
chmod 600 .security_advisor/*.json
```

---

## 📖 Recursos Adicionales

- [HackerOne API Documentation](https://api.hackerone.com/docs)
- [Bugcrowd API Documentation](https://docs.bugcrowd.com/api/)
- [Intigriti API Documentation](https://api.intigriti.com/docs)
- [OWASP Bug Bounty Guide](https://owasp.org/www-project-bug-bounty/)
- [Bug Bounty Platforms List](https://github.com/vavkamil/awesome-bugbounty)

---

## 📜 Glosario

| Término | Descripción |
|--------|-------------|
| **Bug Bounty** | Programa de recompensas por encontrar vulnerabilidades |
| **Finding** | Vulnerabilidad identificada |
| **Scope** | Dominios/IPs donde se permiten pruebas |
| **Severity** | Gravedad de la vulnerabilidad (Critical, High, Medium, Low, Info) |
| **Impact** | Impacto potencial de la vulnerabilidad |
| **CVSS** | Common Vulnerability Scoring System |
| **CWE** | Common Weakness Enumeration |
| **PoC** | Proof of Concept |
| **Triaged** | Finding revisado y clasificado |
| **Duplicate** | Finding ya reportado |

---

**Security Advisor Auditor v3.0 - Módulo de Bug Bounty** 🎯
