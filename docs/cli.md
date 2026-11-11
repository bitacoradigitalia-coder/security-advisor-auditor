# 💻 CLI - Interfaz de Línea de Comandos

El CLI principal de **Security Advisor Auditor** es `python scripts/audit.py`.

---

## 📋 Tabla de Contenidos

- [🎯 Comandos Principales](#-comandos-principales)
- [📖 Descripción de Comandos](#-descripción-de-comandos)
- [🔧 Opciones Globales](#-opciones-globales)
- [📝 Ejemplos Prácticos](#-ejemplos-prácticos)
- [🎨 Personalización](#-personalización)

---

## 🎯 Comandos Principales

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `scan` | Análisis completo (estático + activo) | `python scripts/audit.py scan /ruta --output ./report` |
| `fuzz` | Fuzzing de parámetros | `python scripts/audit.py fuzz https://api.example.com --param id` |
| `exploit` | Explotación controlada | `python scripts/audit.py exploit URL --vuln sqli --permission-file perm.json` |
| `bugbounty` | Gestión de Bug Bounty | `python scripts/audit.py bugbounty add-program --name "Programa"` |
| `auth` | Gestión de autenticación | `python scripts/audit.py auth add-session --name admin` |
| `poc` | Generación de PoCs | `python scripts/audit.py poc generate --finding audit.json` |
| `report` | Generación de reportes | `python scripts/audit.py report audit.json --format html` |
| `tools` | Listar herramientas disponibles | `python scripts/audit.py tools` |
| `validate-skill` | Validar skill | `python scripts/audit.py validate-skill .` |
| `extract-zip` | Extraer ZIP de forma segura | `python scripts/audit.py extract-zip archivo.zip --output ./salida` |
| `idor` | Detección IDOR/BOLA | `python scripts/audit.py idor URL --session1 admin --session2 user` |
| `cvss` | Calculadora CVSS 3.1 | `python scripts/audit.py cvss --vuln-type sqli --json` |

---

## 📖 Descripción de Comandos

### 🔍 `scan` - Análisis Completo

Realiza análisis estático y/o activo de un objetivo.

**Opciones principales:**
```
--target, -t          URL o ruta al objetivo
--output, -o         Directorio de salida (obligatorio)
--mode               Modo de análisis: QUICK, STANDARD, DEEP (default: QUICK)
--active             Habilitar escaneo activo
--session            Nombre de sesión para autenticación
--nuclei             Usar Nuclei para escaneo de vulnerabilidades
--fuzz               Habilitar fuzzing
--scan-js            Escanear archivos JavaScript
--scan-forms         Escanear formularios HTML
--scan-headers       Verificar headers de seguridad
--scan-cookies       Analizar cookies
--max-file-bytes     Límite de bytes por archivo (default: 1000000)
--max-files          Límite de archivos a analizar (default: 10000)
--max-total-bytes    Límite total de bytes leídos (default: 20000000)
--legacy-report      Generar reporte en formato legacy
```

**Ejemplo completo:**
```bash
python scripts/audit.py scan https://example.com --output ./report \
  --active --nuclei --fuzz --session admin \
  --max-file-bytes 500000 --max-files 2000
```

### 🎯 `fuzz` - Fuzzing de Parámetros

Pruebas de fuzzing en parámetros de URLs.

**Opciones principales:**
```
--target, -t          URL base para fuzzing
--param, -p          Parámetro(s) a fuzzar (puede repetirse)
--wordlist, -w       Archivo wordlist personalizado
--threads            Número de hilos (default: 5)
--timeout            Timeout por request en segundos (default: 10)
--delay              Delay entre requests en segundos (default: 0.1)
--output, -o         Directorio de salida
```

**Ejemplo:**
```bash
python scripts/audit.py fuzz https://example.com/api --param id --param user \
  --wordlist custom.txt --threads 10 --output ./fuzz-results
```

### ⚡ `exploit` - Explotación Controlada

Ejecución controlada de exploits con permisos explícitos.

**⚠️ ADVERTENCIA**: Requiere archivo de permisos válido. La explotación sin permiso es **ilegal y antiética**.

**Opciones principales:**
```
--target, -t          URL objetivo
--vuln, -v           Tipo de vulnerabilidad: sqli, xss, rce, lfi, ssrf, idor, xxe
--permission-file    Archivo de permisos (obligatorio)
--output, -o         Directorio de salida
--create-permission  Crear archivo de permisos en lugar de explotar
--expires            Fecha de expiración de permisos
--vuln-type          Tipos de vulnerabilidades permitidos
--scope              Scope de permisos (ej: *.example.com)
--notes              Notas para el archivo de permisos
```

**Ejemplo - Crear permisos:**
```bash
python scripts/audit.py exploit --create-permission \
  --target https://example.com \
  --vuln-type sqli,xss,rce \
  --expires 2024-12-31 \
  --scope "*.example.com" \
  --notes "Pruebas autorizadas" \
  --output permissions.json
```

**Ejemplo - Explotar:**
```bash
python scripts/audit.py exploit https://example.com/api?id=1 \
  --vuln sqli \
  --permission-file permissions.json \
  --output ./exploits
```

### 🐞 `bugbounty` - Gestión de Bug Bounty

Gestión completa de programas y findings de Bug Bounty.

**Subcomandos:**
```
add-program      Añadir un nuevo programa
list-programs    Listar programas existentes
add-finding      Añadir un finding a un programa
delete-finding    Eliminar un finding
list-findings    Listar findings de un programa
prioritize       Priorizar findings
stats            Mostrar estadísticas de un programa
```

**Ejemplo - Añadir programa:**
```bash
python scripts/audit.py bugbounty add-program \
  --name "Example Inc" \
  --scope example.com,api.example.com \
  --platform hackerone \
  --reward-range "$100-$1000"
```

**Ejemplo - Añadir finding:**
```bash
python scripts/audit.py bugbounty add-finding \
  --program "Example Inc" \
  --title "SQL Injection in /api/users" \
  --severity critical \
  --vuln-type sqli \
  --target https://api.example.com/users?id=1 \
  --description "Inyección SQL en parámetro id" \
  --cvss 9.8 \
  --cwe 89
```

**Ejemplo - Priorizar findings:**
```bash
python scripts/audit.py bugbounty prioritize \
  --program "Example Inc" \
  --output prioritized.json
```

### 🔐 `auth` - Gestión de Autenticación

Gestión de sesiones autenticadas para escaneos.

**Subcomandos:**
```
add-session      Añadir una nueva sesión
list-sessions    Listar sesiones existentes
remove-session   Eliminar una sesión
```

**Opciones para add-session:**
```
--name             Nombre de la sesión
--cookie           Cookie(s) de autenticación (puede repetirse)
--auth-type        Tipo: basic, bearer, digest, oauth2 (default: cookie)
--token            Token para bearer auth
--username         Usuario para basic auth
--password         Contraseña para basic auth
--client-id        Client ID para OAuth2
--client-secret    Client secret para OAuth2
```

**Ejemplo - Sesión con cookies:**
```bash
python scripts/audit.py auth add-session \
  --name admin \
  --cookie session_id=abc123 \
  --cookie auth_token=xyz456
```

**Ejemplo - Sesión con bearer token:**
```bash
python scripts/audit.py auth add-session \
  --name api_user \
  --auth-type bearer \
  --token abcdef123456
```

### 📄 `poc` - Generación de PoCs

Generación automática de Proof of Concept.

**Opciones principales:**
```
--finding           Archivo JSON con el finding
--language          Lenguaje: python, bash, curl, powershell
--output, -o        Archivo de salida
--simple            Generar PoC simple (sin verificación)
--verbose           Incluir comentarios detallados
```

**Ejemplo:**
```bash
python scripts/audit.py poc generate \
  --finding audit.json \
  --language python \
  --output ./poc.py
```

### 📊 `report` - Generación de Reportes

Generación de reportes en múltiples formatos.

**Opciones principales:**
```
--input, -i         Archivo de entrada (audit.json)
--output, -o        Directorio de salida
--format            Formato: markdown, html, json, sarif (default: json)
--template-path     Ruta a plantilla personalizada
--severity-filter   Filtrar por severidad: critical, high, medium, low, info
--type-filter       Filtrar por tipo: vulnerability, weakness, risk, hardening, info
--include-confirmed Incluir solo hallazgos confirmados
--include-fp        Incluir falsos positivos
--redact-secrets    Redactar secretos en el reporte (default: true)
```

**Ejemplo:**
```bash
python scripts/audit.py report audit.json \
  --output ./report \
  --format html \
  --severity-filter critical,high \
  --type-filter vulnerability
```

### 🔧 `tools` - Herramientas Disponibles

Muestra todas las herramientas y módulos disponibles.

```bash
python scripts/audit.py tools
```

### ✅ `validate-skill` - Validación de Skill

Valida la integridad de la skill.

```bash
python scripts/audit.py validate-skill .
```

### 📦 `extract-zip` - Extracción Segura de ZIP

Extrae archivos ZIP de forma segura con validaciones.

**Opciones principales:**
```
--input, -i         Archivo ZIP de entrada
--output, -o        Directorio de salida
--max-file-size     Tamaño máximo por archivo (default: 50MB)
--max-total-size    Tamaño máximo total (default: 50MB)
--max-entries       Número máximo de entradas (default: 1000)
```

**Ejemplo:**
```bash
python scripts/audit.py extract-zip input.zip --output ./extracted
```

### 🔍 `idor` - Detección IDOR/BOLA

Detección de vulnerabilidades IDOR (Insecure Direct Object Reference) y BOLA (Broken Object Level Authorization).

**Opciones:**
```
--target, -t       URL base
--session1        Nombre de la primera sesión (ej: admin)
--session2        Nombre de la segunda sesión (ej: user)
--param           Parámetro a testear
--output, -o      Directorio de salida
```

**Ejemplo:**
```bash
python scripts/audit.py idor https://example.com/api/users \
  --session1 admin \
  --session2 user \
  --param id \
  --output ./idor-results
```

### 🎯 `cvss` - Calculadora CVSS 3.1

Calculadora de puntuación CVSS 3.1.

**Opciones:**
```
--vuln-type        Tipo de vulnerabilidad (sqli, xss, rce, etc.)
--vector           Vector CVSS completo (ej: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
--json             Salida en formato JSON
--interactive      Modo interactivo
```

**Ejemplo:**
```bash
python scripts/audit.py cvss --vuln-type sqli --json
```

---

## 🔧 Opciones Globales

Todas las opciones globales aplicables a todos los comandos:

```
--help, -h         Mostrar ayuda
--version, -v      Mostrar versión
--verbose          Modo verboso
--debug            Modo debug (más detalles)
--config           Archivo de configuración personalizado
--storage-path     Ruta de almacenamiento para datos persistentes
--log-level        Nivel de log: DEBUG, INFO, WARNING, ERROR, CRITICAL
--no-color         Deshabilitar colores en la salida
--quiet, -q        Modo silencioso (solo errores)
```

---

## 📝 Ejemplos Prácticos

### 🎯 Escenario 1: Análisis Estático de Repositorio

```bash
# Clonar repositorio
git clone https://github.com/usuario/proyecto.git
cd proyecto

# Análisis rápido
python ../security-advisor-auditor/scripts/audit.py scan . --output ./informe

# Análisis profundo con límites personalizados
python ../security-advisor-auditor/scripts/audit.py scan . \
  --output ./informe-profundos \
  --mode DEEP \
  --max-file-bytes 500000 \
  --max-files 2000

# Generar reporte en HTML
python ../security-advisor-auditor/scripts/audit.py report ./informe/audit.json \
  --output ./reporte-final \
  --format html
```

### 🌐 Escenario 2: Escaneo Activo de Aplicación Web

```bash
# Escaneo básico
python scripts/audit.py scan https://example.com --output ./report --active

# Escaneo con autenticación
python scripts/audit.py auth add-session --name admin --cookie session_id=abc123
python scripts/audit.py scan https://example.com --output ./report --active --session admin

# Escaneo completo con Nuclei
python scripts/audit.py scan https://example.com --output ./report \
  --active --nuclei --fuzz --scan-js --scan-forms --scan-headers
```

### 🐞 Escenario 3: Gestión de Bug Bounty

```bash
# Crear programa
python scripts/audit.py bugbounty add-program \
  --name "Mi Empresa" \
  --scope example.com,api.example.com \
  --platform hackerone

# Escanear aplicación
python scripts/audit.py scan https://example.com --output ./scan-results --active

# Añadir findings desde el escaneo
python scripts/audit.py bugbounty add-finding \
  --program "Mi Empresa" \
  --title "XSS en /search" \
  --severity high \
  --vuln-type xss \
  --target https://example.com/search?q=<script>alert(1)</script>

# Priorizar findings
python scripts/audit.py bugbounty prioritize --program "Mi Empresa" --output prioritized.json

# Generar reporte para el programa
python scripts/audit.py report ./scan-results/audit.json \
  --output ./bugbounty-report \
  --format html \
  --severity-filter critical,high
```

### 🔍 Escenario 4: Pruebas de Fuzzing

```bash
# Fuzzing básico
python scripts/audit.py fuzz https://example.com/api/users --param id --output ./fuzz-results

# Fuzzing con wordlist personalizada
python scripts/audit.py fuzz https://example.com/api/users \
  --param id \
  --wordlist ~/wordlists/sqli.txt \
  --output ./sqli-fuzz

# Fuzzing con múltiples parámetros
python scripts/audit.py fuzz https://example.com/api/search \
  --param q \
  --param page \
  --param sort \
  --threads 10 \
  --delay 0.5 \
  --output ./multi-fuzz
```

### ⚡ Escenario 5: Explotación Controlada (con permisos)

```bash
# Crear archivo de permisos
python scripts/audit.py exploit --create-permission \
  --target https://example.com \
  --vuln-type sqli,xss \
  --expires 2024-12-31 \
  --scope "*.example.com" \
  --notes "Pruebas autorizadas por el equipo de seguridad" \
  --output permissions.json

# Explotar vulnerabilidad
python scripts/audit.py exploit https://example.com/api?id=1 \
  --vuln sqli \
  --permission-file permissions.json \
  --output ./exploits

# Generar PoC
python scripts/audit.py poc generate \
  --finding ./exploits/finding.json \
  --language python \
  --output ./poc.py
```

---

## 🎨 Personalización

### 📁 Archivo de Configuración

Puedes crear un archivo de configuración JSON para evitar repetir opciones:

```json
{
  "default_output": "./reports",
  "default_mode": "STANDARD",
  "rate_limit": 10,
  "user_agent": "SecurityAdvisorAuditor/2.2",
  "storage_path": "./.security_advisor",
  "nuclei_path": "/usr/local/bin/nuclei",
  "wordlists_path": "./wordlists"
}
```

**Usar configuración:**
```bash
python scripts/audit.py scan https://example.com --config config.json
```

### 🎭 Alias de Comandos

Crea alias en tu shell para comandos frecuentes:

```bash
# Bash
alias sa-scan='python ~/security-advisor-auditor/scripts/audit.py scan'
alias sa-fuzz='python ~/security-advisor-auditor/scripts/audit.py fuzz'
alias sa-report='python ~/security-advisor-auditor/scripts/audit.py report'

# Zsh
alias sa-scan='python ~/security-advisor-auditor/scripts/audit.py scan'
alias sa-fuzz='python ~/security-advisor-auditor/scripts/audit.py fuzz'
alias sa-report='python ~/security-advisor-auditor/scripts/audit.py report'
```

### 📦 Wordlists Personalizadas

Puedes añadir tus propias wordlists en `scripts/pentesting/wordlists/` o especificar la ruta:

```bash
python scripts/audit.py fuzz https://example.com/api --param id \
  --wordlist /ruta/a/mi/wordlist.txt --output ./results
```

---

## 🚨 Advertencias de Seguridad

1. **🔒 Permisos explícitos**: La explotación de vulnerabilidades requiere un archivo de permisos válido
2. **🎯 Scope definido**: No exceder el scope autorizado
3. **⚡ Rate limiting**: 10 requests/segundo por defecto para evitar DoS
4. **📝 Documentación**: Registrar todas las acciones para auditoría
5. **🚫 Producción**: No realizar pruebas en producción sin autorización explícita

---

## 📚 Ver También

- [Uso Avanzado](usage.md) - Guías detalladas de uso
- [Módulo de Pentesting](../pentesting.md) - Documentación técnica del módulo
- [Módulo de Bug Bounty](../bugbounty.md) - Documentación técnica del módulo
- [Arquitectura del Sistema](../architecture.md) - Diseño general
