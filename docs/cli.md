# Referencia CLI

Opciones extraídas del parser de `scripts/audit.py`. Consulta `python scripts/audit.py COMANDO --help` para la ayuda de tu checkout.

Las opciones globales van **antes del subcomando**. Los ejemplos y límites operativos están en [Uso](usage.md). SCA dispone de [CLI independiente](usage.md#sca); IaC se utiliza mediante la API Python.

## Opciones globales

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--scope-config` | No | Archivo de configuracion de alcance (JSON) |
| `--engagement-id` | No | ID del engagement para autorizacion |
| `--engagement-file` | No | Archivo de engagements (JSON) |
| `--no-scope-validation` | No | Deshabilitar validacion de alcance (NO RECOMENDADO) |

## scan

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `target` | Sí | Ruta del repositorio o URL del objetivo |
| `--output` | Sí | Directorio de salida |
| `--mode` | No | Modo de análisis estático (QUICK, STANDARD, DEEP) Valores: QUICK, STANDARD, DEEP. |
| `--max-file-bytes` | No |  |
| `--max-files` | No |  |
| `--max-total-bytes` | No |  |
| `--max-depth` | No |  |
| `--max-seconds` | No |  |
| `--max-memory-bytes` | No | Límite de memoria del subproceso parser y presupuesto estimado AST |
| `--max-findings` | No |  |
| `--max-ast-nodes` | No |  |
| `--max-call-depth` | No |  |
| `--legacy-report` | No | Exportar únicamente campos del contrato v2.0 |
| `--active` | No | Habilitar escaneo activo |
| `--session` | No | Nombre de la sesión autenticada |
| `--nuclei` | No | Ejecutar Nuclei (requiere instalación) |
| `--nuclei-templates` | No | Plantillas de Nuclei (ej: sqli,xss) |
| `--fuzz` | No | Habilitar fuzzing de parámetros |
| `--fuzz-params` | No | Parámetros a fuzzar (ej: id,user,token) |
| `--scan-js` | No | Escanear archivos JavaScript |
| `--scan-forms` | No | Escanear formularios |
| `--scan-headers` | No | Escanear headers |
| `--scan-cookies` | No | Escanear cookies |

## fuzz

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `target` | Sí | URL del objetivo |
| `--output` | Sí | Directorio de salida |
| `--param` | No | Parámetro a fuzzar (puede repetirse) |
| `--params` | No | Lista de parámetros separados por comas |
| `--wordlist` | No | Ruta al wordlist personalizado |
| `--vuln-types` | No | Tipos de vulnerabilidades a probar (ej: sqli,xss) |
| `--methods` | No | Métodos HTTP a probar (ej: GET,POST,PUT) |
| `--session` | No | Nombre de la sesión autenticada |
| `--threads` | No | Número de hilos |
| `--timeout` | No | Timeout en segundos |
| `--delay` | No | Retraso entre requests |

## exploit

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `target` | Sí | URL del objetivo |
| `--vuln` | Sí | Tipo de vulnerabilidad Valores: sqli, xss, ssrf, rce, lfi, rfi, idor, xxe, csrf, command-injection, path-traversal, open-redirect. |
| `--param` | No | Parámetro vulnerable |
| `--payload` | No | Payload personalizado |
| `--method` | No | Método HTTP Valores: GET, POST, PUT, DELETE, PATCH. |
| `--session` | No | Nombre de la sesión autenticada |
| `--permission-file` | Sí | Archivo de permisos (obligatorio para explotación) |
| `--output` | No | Directorio de salida para resultados |
| `--generate-poc` | No | Generar PoC automático |

## bugbounty

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |

## bugbounty add-program

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--name` | Sí | Nombre del programa |
| `--scope` | Sí | Scope (ej: example.com,api.example.com) |
| `--rules` | No | Reglas del programa |
| `--platform` | No | Plataforma de Bug Bounty Valores: hackerone, bugcrowd, intigriti, other. |
| `--api-token` | No | API token para la plataforma |

## bugbounty add-finding

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--program` | Sí | Nombre del programa |
| `--file` | Sí | Archivo audit.json con hallazgos |
| `--finding-id` | No | ID específico del hallazgo |
| `--severity` | No | Severidad del hallazgo Valores: info, low, medium, high, critical. |

## bugbounty list-programs

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |

## bugbounty list-findings

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--program` | No | Nombre del programa (opcional) |

## bugbounty generate-report

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--finding-id` | Sí | ID del hallazgo |
| `--format` | No | Formato del reporte Valores: markdown, html, json. |
| `--output` | No | Archivo de salida |
| `--platform` | No | Formato específico de la plataforma Valores: hackerone, bugcrowd, generic. |

## bugbounty submit

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--finding-id` | Sí | ID del hallazgo |
| `--platform` | Sí | Plataforma de destino Valores: hackerone, bugcrowd. |
| `--program-handle` | Sí | Handle del programa |
| `--api-token` | Sí | API token |
| `--dry-run` | No | Simular envío sin enviar |

## idor

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `target` | Sí | URL base del objetivo |
| `--session1` | Sí | Nombre de la primera sesión (ej: admin) |
| `--session2` | Sí | Nombre de la segunda sesión (ej: user) |
| `--endpoints` | No | Lista de endpoints a probar (separados por comas) |
| `--methods` | No | Métodos HTTP a probar (ej: GET,POST) |
| `--output` | Sí | Directorio de salida |
| `--timeout` | No | Timeout en segundos |
| `--delay` | No | Retraso entre requests (segundos) |
| `--max-endpoints` | No | Máximo número de endpoints a probar |

## cvss

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `vector` | No | Vector CVSS (ej: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") |
| `--av` | No | Attack Vector (N, A, L, P) Valores: N, A, L, P. |
| `--ac` | No | Attack Complexity (L, H) Valores: L, H. |
| `--pr` | No | Privileges Required (N, L, H) Valores: N, L, H. |
| `--ui` | No | User Interaction (N, R) Valores: N, R. |
| `--s` | No | Scope (U, C) Valores: U, C. |
| `--c` | No | Confidentiality (N, L, H) Valores: N, L, H. |
| `--i` | No | Integrity (N, L, H) Valores: N, L, H. |
| `--a` | No | Availability (N, L, H) Valores: N, L, H. |
| `--vuln-type` | No | Tipo de vulnerabilidad (sqli, xss, idor, etc.) |
| `--json` | No | Salida en formato JSON |

## ai-defense

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `text` | No | Texto a analizar para detectar patrones de IA adversaria |
| `--input-file` | No | Archivo de entrada con texto a analizar |
| `--monitor` | No | Modo monitor: analizar múltiples requests (para integración con APIs) |
| `--block-severity` | No | Severidad mínima para bloquear (CRITICAL, HIGH, MEDIUM, LOW, INFO) Valores: CRITICAL, HIGH, MEDIUM, LOW, INFO. |
| `--list-patterns` | No | Listar todos los patrones de detección |
| `--pattern-type` | No | Filtrar patrones por tipo de amenaza Valores: PROMPT_INJECTION, JAILBREAK, DATA_EXFILTRATION, CODE_INJECTION, MODEL_MANIPULATION, DENIAL_OF_SERVICE. |
| `--output` | No | Directorio de salida para reportes |
| `--json` | No | Salida en formato JSON |

## auth

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |

## auth add-session

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--name` | Sí | Nombre de la sesión |
| `--cookies` | No | Cookies (ej: "session=abc; auth=xyz") |
| `--headers` | No | Headers (JSON) |
| `--token` | No | Bearer token |
| `--username` | No | Usuario para Basic Auth |
| `--password` | No | Contraseña para Basic Auth |
| `--base-url` | No | URL base del objetivo |
| `--auth-type` | No | Tipo de autenticación Valores: cookie, bearer, basic, oauth2. |

## auth list-sessions

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |

## auth remove-session

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--name` | Sí | Nombre de la sesión |

## auth oauth2-token

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `--token-url` | Sí | URL del endpoint de token |
| `--client-id` | Sí | Client ID |
| `--client-secret` | Sí | Client secret |
| `--scope` | No | Scope solicitado |
| `--grant-type` | No | Tipo de grant |

## report

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `input` | Sí | Archivo audit.json de entrada |
| `--output` | Sí | Directorio o archivo de salida |
| `--format` | No | Formato del reporte Valores: markdown, html, pdf, json, sarif. |
| `--template` | No | Plantilla personalizada |
| `--include-false-positives` | No | Incluir falsos positivos |
| `--severity-filter` | No | Filtrar por severidad (ej: high,critical) |

## poc

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `finding-id` | Sí | ID del hallazgo |
| `--input` | Sí | Archivo audit.json |
| `--output` | No | Archivo de salida (default: poc_{finding-id}.py) |
| `--language` | No | Lenguaje del PoC Valores: python, bash, curl. |
| `--target` | No | URL del objetivo (sobreescribe el del hallazgo) |

## validate-skill

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `skill` | Sí |  |

## extract-zip

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
| `archive` | Sí |  |
| `--output` | Sí |  |

## tools

| Argumento | Requerido | Descripción |
|---|---|---|
| `-h, --help` | No | show this help message and exit |
