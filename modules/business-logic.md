# Lógica de negocio — fases 6, 9–12, 21

Construir estados, transiciones y efectos de cada workflow; revisar idempotencia
como autorización, email como prueba de propiedad, falsa rotación de tokens,
mutación pública de perfiles, acciones costosas en roles inferiores, fuga
cross-tenant y locks globales. Estas comprobaciones originales permanecen
obligatorias; no las implementa la heurística local.

Verificar invariantes de pago/capacidad, retries, rollback y fallos parciales.
Pruebas de regresión con datos sintéticos y concurrencia en sandbox autorizado.
Priorizar por alcance/impacto observado; no recomendar migración por moda ni
clasificar todo lock global como crítico. Costes/quotas actuales requieren
fuente actual y contexto del despliegue. Fuente: [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/).
