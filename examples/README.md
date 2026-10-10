# Objetivos sintéticos

`vulnerable/`: sinks deliberados; `safe/`: usos sin shell y placeholders cortos.
Son inputs estáticos, nunca módulos para importar ni pruebas a ejecutar.

```text
python scripts/audit.py scan examples/vulnerable --output ../example-vulnerable-report
python scripts/audit.py scan examples/safe --output ../example-safe-report
```

Esperado: candidatos CWE-78/95/502/295/79 en vulnerable; cero señales en safe.
No significa ausencia de todos los riesgos. Tokens sintéticos solo se construyen
en temporales por unittest, sin credenciales reales en fixtures.
