# Índice de conocimiento ampliable

Cargar solo la referencia necesaria para el problema observado. No copiar
manuales completos. Añadir notas técnicas propias en `references/` y enlazarlas
desde este índice; declarar fuente, licencia, versión/fecha y fases cubiertas.
Cada nota debe separar fuente, observación del objetivo e inferencia del auditor.
Verificar versiones/advisories online solo con acceso y consentimiento apropiados;
si no se puede, marcar conocimiento desactualizable y pendiente de verificación.

| Fuente primaria | Uso |
| --- | --- |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | Controles web, auth, datos |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) | Diseño de pruebas web autorizadas |
| [OWASP API Security](https://owasp.org/www-project-api-security/) | Autorización de objetos/funciones y consumo |
| [OWASP MASVS](https://mas.owasp.org/MASVS/) | Clientes móviles |
| [CWE](https://cwe.mitre.org/) | Taxonomía de debilidades; no identificación CVE |
| [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) | Desarrollo seguro y supply chain |
| [MITRE ATT&CK](https://attack.mitre.org/) | Contexto adversario cuando pertinente |

Consultar guías de herramientas mediante `python scripts/audit.py tools`.
Este índice contiene enlaces y pautas propias; no es una copia offline de normas
ni una base actualizada de vulnerabilidades de dependencias.
