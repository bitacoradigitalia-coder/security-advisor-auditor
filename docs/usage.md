# 📖 Guía de Uso - Security Advisor Auditor

Esta guía proporciona ejemplos prácticos y flujos de trabajo para utilizar **Security Advisor Auditor** de manera efectiva.

---

## 🗂️ Tabla de Contenidos

- [🎯 Flujos de Trabajo Recomendados](#-flujos-de-trabajo-recomendados)
- [📁 Análisis de Repositorios Locales](#-análisis-de-repositorios-locales)
- [🌐 Escaneo de Aplicaciones Web](#-escaneo-de-aplicaciones-web)
- [🐞 Gestión de Programas Bug Bounty](#-gestión-de-programas-bug-bounty)
- [🔍 Pruebas de Penetración](#-pruebas-de-penetración)
- [📊 Generación de Reportes](#-generación-de-reportes)
- [📦 Análisis SCA y IaC](#-análisis-sca-y-iac)
- [⚡ Automatización y CI/CD](#-automatización-y-cicd)
- [🎨 Consejos y Mejores Prácticas](#-consejos-y-mejores-prácticas)

---

## 🎯 Flujos de Trabajo Recomendados

### 🏆 Flujo 1: Auditoría Completa de Proyecto

**Objetivo**: Realizar una auditoría completa de un proyecto de software.

```bash
# 1. Clonar el repositorio a auditar
git clone https://github.com/usuario/proyecto.git
cd proyecto

# 2. Crear directorio para resultados
mkdir ../auditoria-proyecto-$(date +%Y%m%d)
cd ../auditoria-proyecto-$(date +%Y%m%d)

# 3. Análisis estático profundo
python ../security-advisor-auditor/scripts/audit.py scan ../proyecto \
  --output ./estatico \
  --mode DEEP \
  --max-file-bytes 500000 \
  --max-files 2000 \
  --max-total-bytes 5000000

# 4. Análisis SCA (Software Composition Analysis)
python ../security-advisor-auditor/scripts/audit.py sca generate-sbom \
  --requirements ../proyecto/requirements.txt \
  --output sbom.json

python ../security-advisor-auditor/scripts/audit.py sca scan \
  --sbom sbom.json \
  --output vulnerabilidades-sca.json

# 5. Análisis IaC (si hay archivos de infraestructura)
python ../security-advisor-auditor/scripts/audit.py iac scan ../proyecto/infra/ \
  --output ./iac

# 6. Generar reporte unificado
python ../security-advisor-auditor/scripts/audit.py report ./estatico/audit.json \
  --output ./reporte-final \
  --format html \
  --severity-filter critical,high,medium

# 7. Validar skill
python ../security-advisor-auditor/scripts/audit.py validate-skill ..
```

**Resultado**: Directorio completo con análisis estático, SCA, IaC y reporte HTML.

---

### 🏆 Flujo 2: Escaneo de Aplicación Web en Producción (con permisos)

**Objetivo**: Escanear una aplicación web en producción de manera segura.

```bash
# 1. Crear archivo de permisos
python scripts/audit.py exploit --create-permission \
  --target https://example.com \
  --vuln-type sqli,xss,rce,lfi,ssrf,idor,xxe \
  --expires 2024-12-31 \
  --scope "*.example.com" \
  --notes "Pruebas autorizadas por el equipo de seguridad de Example Inc. Contacto: security@example.com" \
  --output permissions.json

# 2. Configurar autenticación (si es necesario)
python scripts/audit.py auth add-session \
  --name admin \
  --cookie session_id=abc123def456 \
  --cookie auth_token=xyz789

# 3. Escaneo activo con Nuclei
python scripts/audit.py scan https://example.com \
  --output ./escaneo-$(date +%Y%m%d) \
  --active \
  --nuclei \
  --session admin \
  --scan-js \
  --scan-forms \
  --scan-headers \
  --scan-cookies

# 4. Fuzzing de endpoints críticos
python scripts/audit.py fuzz https://example.com/api/users \
  --param id \
  --param name \
  --output ./fuzzing-users

python scripts/audit.py fuzz https://example.com/api/search \
  --param q \
  --wordlist scripts/pentesting/wordlists/sqli.txt \
  --output ./fuzzing-search

# 5. Detección IDOR
python scripts/audit.py idor https://example.com/api/users \
  --session1 admin \
  --session2 user \
  --param id \
  --output ./idor-results

# 6. Generar reporte
python scripts/audit.py report ./escaneo-*/audit.json \
  --output ./reporte-web \
  --format html \
  --severity-filter critical,high
```

**Resultado**: Escaneo completo con detección de vulnerabilidades y reporte profesional.

---

### 🏆 Flujo 3: Gestión de Programa Bug Bounty

**Objetivo**: Gestionar un programa de Bug Bounty completo.

```bash
# 1. Crear programa
python scripts/audit.py bugbounty add-program \
  --name "Example Inc" \
  --scope example.com,api.example.com,*.example.com \
  --platform hackerone \
  --reward-range "$100-$5000" \
  --description "Programa de recompensas por vulnerabilidades"

# 2. Escanear aplicación
python scripts/audit.py scan https://example.com \
  --output ./scan-$(date +%Y%m%d) \
  --active \
  --nuclei

# 3. Añadir findings manualmente
python scripts/audit.py bugbounty add-finding \
  --program "Example Inc" \
  --title "Stored XSS en /comments" \
  --severity critical \
  --vuln-type xss \
  --target https://example.com/comments \
  --description "Vulnerabilidad de Stored XSS en el sistema de comentarios" \
  --steps "1. Ingresar payload: <script>alert(1)</script> 2. Publicar comentario 3. Ver que se ejecuta al cargar la página" \
  --cvss 9.1 \
  --cwe 79 \
  --impact "Ejecución de código JavaScript arbitrario en el contexto de otros usuarios" \
  --remediation "Implementar sanitización de entrada y encoding de salida"

# 4. Importar findings desde escaneo
# (Puedes parsear el audit.json y añadir findings automáticamente)
python -c "
import json
with open('./scan-20241115/audit.json', 'r') as f:
    audit = json.load(f)
for finding in audit.get('findings', []):
    # Añadir cada finding al programa
    pass
"

# 5. Priorizar findings
python scripts/audit.py bugbounty prioritize \
  --program "Example Inc" \
  --output prioritized-$(date +%Y%m%d).json

# 6. Generar estadísticas
python scripts/audit.py bugbounty stats --program "Example Inc"

# 7. Exportar reporte para el programa
python scripts/audit.py report ./scan-*/audit.json \
  --output ./reporte-bugbounty \
  --format html \
  --template-path templates/bugbounty-template.md
```

**Resultado**: Programa de Bug Bounty completamente gestionado con findings priorizados.

---

## 📁 Análisis de Repositorios Locales

### Análisis Básico

```bash
# Análisis rápido (modo QUICK)
python scripts/audit.py scan /ruta/al/repositorio --output ./informe-rapido

# Análisis estándar (recomendado)
python scripts/audit.py scan /ruta/al/repositorio --output ./informe --mode STANDARD

# Análisis profundo (más lento, más completo)
python scripts/audit.py scan /ruta/al/repositorio --output ./informe-profundo --mode DEEP
```

### Análisis con Límites Personalizados

```bash
# Para repositorios grandes
python scripts/audit.py scan /ruta/al/repositorio --output ./informe \
  --max-file-bytes 1000000 \
  --max-files 5000 \
  --max-total-bytes 50000000

# Para repositorios con muchos archivos
python scripts/audit.py scan /ruta/al/repositorio --output ./informe \
  --max-files 10000 \
  --max-depth 32
```

### Análisis Selectivo

```bash
# Analizar solo archivos Python
python scripts/audit.py scan /ruta/al/repositorio --output ./informe \
  --include-patterns "*.py"

# Excluir directorios específicos
python scripts/audit.py scan /ruta/al/repositorio --output ./informe \
  --exclude-patterns "tests/*","venv/*","node_modules/*"
```

### Análisis Incremental

```bash
# Primera ejecución (completa)
python scripts/audit.py scan /ruta/al/repositorio --output ./informe-base

# Ejecución posterior (comparar con base)
python scripts/audit.py scan /ruta/al/repositorio --output ./informe-nuevo \
  --baseline ./informe-base/audit.json
```

---

## 🌐 Escaneo de Aplicaciones Web

### Escaneo Básico

```bash
# Escaneo sin autenticación
python scripts/audit.py scan https://example.com --output ./escaneo --active

# Escaneo con autenticación
python scripts/audit.py auth add-session --name test-user --cookie session=abc123
python scripts/audit.py scan https://example.com --output ./escaneo --active --session test-user
```

### Escaneo con Nuclei

```bash
# Escaneo con Nuclei (usando plantillas por defecto)
python scripts/audit.py scan https://example.com --output ./escaneo --active --nuclei

# Escaneo con plantillas específicas
python scripts/audit.py scan https://example.com --output ./escaneo --active --nuclei \
  --nuclei-templates sqli,xss,ssrf,rce

# Usar Nuclei desde ruta personalizada
python scripts/audit.py scan https://example.com --output ./escaneo --active --nuclei \
  --nuclei-path /usr/local/bin/nuclei
```

### Escaneo Completo

```bash
# Escaneo con todas las opciones habilitadas
python scripts/audit.py scan https://example.com --output ./escaneo-completo \
  --active \
  --nuclei \
  --fuzz \
  --scan-js \
  --scan-forms \
  --scan-headers \
  --scan-cookies \
  --scan-cors
```

### Descubrimiento de Endpoints

```bash
# Descubrimiento básico
python scripts/audit.py scan https://example.com --output ./descubrimiento --active

# Descubrimiento con wordlists personalizadas
python scripts/audit.py scan https://example.com --output ./descubrimiento \
  --active \
  --wordlist-path /ruta/a/wordlists/
```

---

## 🐞 Gestión de Programas Bug Bounty

### Creación de Programa

```bash
# Crear programa básico
python scripts/audit.py bugbounty add-program \
  --name "Mi Empresa" \
  --scope example.com

# Crear programa completo
python scripts/audit.py bugbounty add-program \
  --name "Mi Empresa" \
  --scope example.com,api.example.com,*.example.com \
  --platform hackerone \
  --reward-range "$100-$5000" \
  --description "Programa de recompensas por vulnerabilidades críticas" \
  --start-date 2024-01-01 \
  --end-date 2024-12-31
```

### Gestión de Findings

```bash
# Añadir finding básico
python scripts/audit.py bugbounty add-finding \
  --program "Mi Empresa" \
  --title "SQL Injection" \
  --severity critical \
  --vuln-type sqli \
  --target https://example.com/api/users?id=1

# Añadir finding completo
python scripts/audit.py bugbounty add-finding \
  --program "Mi Empresa" \
  --title "SQL Injection en endpoint /api/users" \
  --severity critical \
  --vuln-type sqli \
  --target https://example.com/api/users?id=1 \
  --description "Vulnerabilidad de inyección SQL en el parámetro id" \
  --steps "1. Enviar: GET /api/users?id=1' OR '1'='1 2. Observar que devuelve todos los usuarios" \
  --cvss 9.8 \
  --cwe 89 \
  --impact "Acceso no autorizado a datos de todos los usuarios" \
  --remediation "Usar consultas parametrizadas en lugar de concatenación de strings" \
  --references "https://owasp.org/www-community/attacks/SQL_Injection"
```

### Priorización y Estadísticas

```bash
# Priorizar findings
python scripts/audit.py bugbounty prioritize \
  --program "Mi Empresa" \
  --output prioritized.json \
  --method weighted \
  --weights severity=0.4,impact=0.3,exploitability=0.2,scope=0.1

# Obtener estadísticas
python scripts/audit.py bugbounty stats --program "Mi Empresa"

# Listar programas
python scripts/audit.py bugbounty list-programs

# Listar findings de un programa
python scripts/audit.py bugbounty list-findings --program "Mi Empresa" \
  --severity-filter critical,high
```

### Exportación

```bash
# Exportar a JSON
python scripts/audit.py bugbounty export --program "Mi Empresa" --output bugbounty-data.json

# Exportar a CSV
python scripts/audit.py bugbounty export --program "Mi Empresa" --output bugbounty-data.csv --format csv

# Exportar reporte para plataforma
python scripts/audit.py report ./audit.json --output ./reporte-hackerone --format markdown
```

---

## 🔍 Pruebas de Penetración

### Fuzzing

```bash
# Fuzzing básico
python scripts/audit.py fuzz https://example.com/api/users --param id --output ./fuzz-results

# Fuzzing con múltiples parámetros
python scripts/audit.py fuzz https://example.com/api/search \
  --param q \
  --param page \
  --param sort \
  --output ./fuzz-results

# Fuzzing con wordlist personalizada
python scripts/audit.py fuzz https://example.com/api/login \
  --param username \
  --wordlist ~/wordlists/usernames.txt \
  --output ./fuzz-usernames

# Fuzzing con configuración avanzada
python scripts/audit.py fuzz https://example.com/api \
  --param id \
  --wordlist scripts/pentesting/wordlists/sqli.txt \
  --threads 10 \
  --timeout 15 \
  --delay 0.5 \
  --output ./fuzz-sqli
```

### Explotación Controlada

```bash
# Crear archivo de permisos
python scripts/audit.py exploit --create-permission \
  --target https://example.com \
  --vuln-type sqli,xss,rce \
  --expires 2024-12-31 \
  --scope "*.example.com" \
  --output permissions.json

# Explotar SQL Injection
python scripts/audit.py exploit https://example.com/api?id=1 \
  --vuln sqli \
  --permission-file permissions.json \
  --output ./exploits

# Explotar XSS
python scripts/audit.py exploit https://example.com/search?q=test \
  --vuln xss \
  --permission-file permissions.json \
  --payload "<script>alert(1)</script>"

# Explotar SSRF
python scripts/audit.py exploit https://example.com/api?url=http://internal \
  --vuln ssrf \
  --permission-file permissions.json \
  --target-url http://169.254.169.254
```

### Detección IDOR/BOLA

```bash
# Detección básica
python scripts/audit.py idor https://example.com/api/users \
  --session1 admin \
  --session2 user \
  --param id \
  --output ./idor-results

# Detección con múltiples parámetros
python scripts/audit.py idor https://example.com/api/documents \
  --session1 admin \
  --session2 user \
  --session3 guest \
  --param id \
  --param doc_type \
  --output ./idor-results

# Detección con configuración avanzada
python scripts/audit.py idor https://example.com/api \
  --session1 admin \
  --session2 user \
  --param id \
  --threads 5 \
  --timeout 10 \
  --output ./idor-results
```

### Generación de PoCs

```bash
# Generar PoC en Python
python scripts/audit.py poc generate \
  --finding ./exploits/finding.json \
  --language python \
  --output ./poc.py

# Generar PoC en Bash
python scripts/audit.py poc generate \
  --finding ./exploits/finding.json \
  --language bash \
  --output ./poc.sh

# Generar PoC en curl
python scripts/audit.py poc generate \
  --finding ./exploits/finding.json \
  --language curl \
  --output ./poc_curl.sh

# Generar PoC con verificación
python scripts/audit.py poc generate \
  --finding ./exploits/finding.json \
  --language python \
  --output ./poc.py \
  --with-verification
```

---

## 📊 Generación de Reportes

### Reportes Básicos

```bash
# Reporte en JSON (formato por defecto)
python scripts/audit.py report audit.json --output ./reporte

# Reporte en Markdown
python scripts/audit.py report audit.json --output ./reporte --format markdown

# Reporte en HTML
python scripts/audit.py report audit.json --output ./reporte --format html

# Reporte en SARIF 2.1.0
python scripts/audit.py report audit.json --output ./reporte --format sarif
```

### Reportes con Filtros

```bash
# Filtrar por severidad
python scripts/audit.py report audit.json --output ./reporte \
  --format html \
  --severity-filter critical,high

# Filtrar por tipo
python scripts/audit.py report audit.json --output ./reporte \
  --format html \
  --type-filter vulnerability,weakness

# Filtrar por ambos
python scripts/audit.py report audit.json --output ./reporte \
  --format html \
  --severity-filter critical,high \
  --type-filter vulnerability
```

### Reportes con Plantillas

```bash
# Usar plantilla personalizada
python scripts/audit.py report audit.json --output ./reporte \
  --format markdown \
  --template-path templates/custom-template.md

# Plantilla para Bug Bounty
python scripts/audit.py report audit.json --output ./reporte \
  --format markdown \
  --template-path templates/bugbounty-template.md
```

### Reportes Ejecutivos

```bash
# Reporte ejecutivo con estadísticas
python scripts/audit.py report audit.json --output ./reporte-ejecutivo \
  --format html \
  --executive-summary

# Reporte con resumen por módulo
python scripts/audit.py report audit.json --output ./reporte \
  --format html \
  --by-module

# Reporte con timeline
python scripts/audit.py report audit.json --output ./reporte \
  --format html \
  --with-timeline
```

---

## 📦 Análisis SCA y IaC

### SCA (Software Composition Analysis)

```bash
# Generar SBOM (CycloneDX 1.5)
python scripts/audit.py sca generate-sbom \
  --requirements requirements.txt \
  --output sbom.json

# Generar SBOM desde directorio
python scripts/audit.py sca generate-sbom \
  --directory . \
  --output sbom.json

# Escanear vulnerabilidades (offline con cache)
python scripts/audit.py sca scan \
  --sbom sbom.json \
  --output vulnerabilities.json

# Escanear con modo online
python scripts/audit.py sca scan \
  --sbom sbom.json \
  --online \
  --output vulnerabilities-online.json

# Escanear con advisories específicos
python scripts/audit.py sca scan \
  --sbom sbom.json \
  --advisories-path advisories.json \
  --output vulnerabilities.json
```

### IaC (Infraestructura como Código)

```bash
# Analizar archivos Docker
python scripts/audit.py iac scan /ruta/a/Dockerfile --output ./iac-report

# Analizar archivos Kubernetes
python scripts/audit.py iac scan /ruta/a/k8s/ --output ./iac-report

# Analizar archivos Terraform
python scripts/audit.py iac scan /ruta/a/terraform/ --output ./iac-report

# Analizar GitHub Actions
python scripts/audit.py iac scan /ruta/al/repo/.github/workflows/ --output ./iac-report

# Analizar con formato específico
python scripts/audit.py iac scan /ruta/a/iac/ --output ./iac-report --format json
```

---

## ⚡ Automatización y CI/CD

### Integración con GitHub Actions

```yaml
name: Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * *'  # Cada día a medianoche

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run security audit
        run: |
          python scripts/audit.py scan . \
            --output ./security-report \
            --mode STANDARD \
            --max-file-bytes 500000 \
            --max-files 2000
      
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: ./security-report/
```

### Integración con GitLab CI

```yaml
security-audit:
  image: python:3.11
  stage: test
  script:
    - pip install -r requirements.txt
    - python scripts/audit.py scan . --output ./security-report --mode STANDARD
  artifacts:
    paths:
      - ./security-report/
    expire_in: 1 week
  only:
    - main
    - develop
    - merge_requests
```

### Script de Automatización Local

```bash
#!/bin/bash
# audit.sh - Script de auditoría automática

REPO_PATH=$1
OUTPUT_DIR="./audit-$(date +%Y%m%d-%H%M%S)"

# Crear directorio de salida
mkdir -p "$OUTPUT_DIR"

# Análisis estático
python scripts/audit.py scan "$REPO_PATH" \
  --output "$OUTPUT_DIR/estatico" \
  --mode DEEP \
  --max-file-bytes 500000 \
  --max-files 2000

# Análisis SCA
if [ -f "$REPO_PATH/requirements.txt" ]; then
  python scripts/audit.py sca generate-sbom \
    --requirements "$REPO_PATH/requirements.txt" \
    --output "$OUTPUT_DIR/sbom.json"
  
  python scripts/audit.py sca scan \
    --sbom "$OUTPUT_DIR/sbom.json" \
    --output "$OUTPUT_DIR/vulnerabilidades-sca.json"
fi

# Generar reporte
python scripts/audit.py report "$OUTPUT_DIR/estatico/audit.json" \
  --output "$OUTPUT_DIR/reporte" \
  --format html

# Validar
python scripts/audit.py validate-skill .

echo "Auditoría completada. Resultados en: $OUTPUT_DIR"
```

---

## 🎨 Consejos y Mejores Prácticas

### 🔍 Para Auditores

1. **Empieza con el análisis estático**: Identifica vulnerabilidades obvias antes de pruebas activas
2. **Usa el modo DEEP para código crítico**: Más lento pero más completo
3. **Siempre obtén permisos por escrito**: Para cualquier prueba activa o explotación
4. **Documenta todo**: Hallazgos, pasos de reproducción, impacto
5. **Prioriza por riesgo**: Enfócate en vulnerabilidades críticas primero
6. **Verifica falsos positivos**: No todas las detecciones son vulnerabilidades reales
7. **Usa múltiples herramientas**: Combina SAST, DAST y revisión manual

### 🛡️ Para Desarrolladores

1. **Integra en tu CI/CD**: Ejecuta auditorías automáticas en cada commit
2. **Corrige vulnerabilidades críticas primero**: No dejes hallazgos críticos sin parchear
3. **Usa el modo QUICK para desarrollo local**: Rápido feedback durante el desarrollo
4. **Revisa los reportes cuidadosamente**: Entiende el contexto de cada hallazgo
5. **Actualiza dependencias regularmente**: Usa SCA para detectar vulnerabilidades conocidas
6. **Sigue las recomendaciones**: Las sugerencias de remediación suelen ser efectivas

### 📊 Para Gestores de Bug Bounty

1. **Define scope claramente**: Evita confusiones sobre qué está permitido
2. **Usa el sistema de priorización**: Para enfocar esfuerzos en hallazgos importantes
3. **Documenta el programa**: Reglas, recompensas, scope, contacto
4. **Responde rápidamente**: A los reportes de los investigadores
5. **Mantén comunicación clara**: Con los investigadores sobre el estado de los reportes
6. **Recompensa el buen trabajo**: Para motivar a los investigadores

### ⚡ Para Optimización de Rendimiento

1. **Usa el modo QUICK para análisis rápidos**: Cuando el tiempo es limitado
2. **Limita el scope**: Analiza solo lo necesario
3. **Usa múltiples hilos en fuzzing**: Para acelerar pruebas de fuzzing
4. **Cachea resultados**: Para evitar análisis redundantes
5. **Usa wordlists optimizadas**: Para fuzzing más eficiente

---

## 🚨 Advertencias Importantes

1. **⚠️ Legalidad**: Solo realiza pruebas con permiso explícito del dueño del sistema
2. **⚠️ Scope**: Nunca excedas el scope autorizado
3. **⚠️ Producción**: No realices pruebas en sistemas de producción sin autorización
4. **⚠️ Daño**: No intentes causar daño, incluso en pruebas autorizadas
5. **⚠️ Responsabilidad**: Eres responsable de tus acciones al usar esta herramienta

---

## 📚 Recursos Adicionales

- [CLI Reference](cli.md) - Referencia completa de la interfaz de línea de comandos
- [Arquitectura del Sistema](architecture.md) - Diseño y componentes
- [Metodología de Auditoría](../references/audit-methodology.md) - 21 fases completas
- [Políticas de Seguridad](../references/ethical-security.md) - Cumplimiento ético
