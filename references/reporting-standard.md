# Estándar de informes v2.0

El CLI produce `audit.json`, `audit.md` y `remediation.md`. JSON es el contrato
de intercambio: [audit-report.schema.json](schemas/audit-report.schema.json).
`validate_report` aplica comprobaciones de clasificación, evidencia, IDs,
líneas, 21 fases y confirmaciones. Es validación del perfil local, no un motor
genérico de JSON Schema. El esquema puede validarse adicionalmente con un
validador Draft 2020-12 independiente.

Markdown incluye resumen, alcance, proyecto/commit, metodología, cobertura,
herramientas, confirmados, pendientes, riesgos/recomendaciones, plan, limitaciones
y referencias. Completar con arquitectura real, decisiones positivas, matriz de
permisos, impactos y pruebas sugeridas siguiendo la metodología original.
El triaje automático no constituye por sí solo el informe completo del agente.

Para completar cobertura, modificar una copia JSON fuera del objetivo y volver
a exportar a destino nuevo:

```text
python scripts/audit.py report /ruta/audit-revisado.json --output /ruta/informe-revisado
```

Los prompts de remediación separan confirmados de investigación. Exigen mínimo
cambio, límites de alcance, preservar comportamiento/tenancy y regresión. Los
comandos de tests/typecheck/lint/build deben existir y revisarse antes de ejecutar;
el motor no ejecuta scripts encontrados en manifests ni los presenta como seguros.
Exportaciones PDF/DOCX quedan a herramientas independientes, no implementadas.
