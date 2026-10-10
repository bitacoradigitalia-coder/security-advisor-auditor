# Web — fases 8, 10, 16, 20

Identificar origen y destino de HTML dinámico, contexto de escape y sanitización.
innerHTML/dangerouslySetInnerHTML son candidatos, no prueba de XSS. Revisar CSP,
cookies, CORS, CSRF cuando corresponde, tokens URL y scripts de terceros contra
configuración efectiva. No comprobar headers de producción sin URL/permiso.
Capturar entrada → render → efecto con ruta alcanzable y precondiciones.

UI y cliente no sustituyen autorización backend. Un token en fragmento evita
envío HTTP pero permanece accesible a JavaScript; POST tampoco autentica.
Fuente: [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).
