# Evaluación v2.1 — 2026-10-11

## Método reproducible

30 pequeños proyectos sintéticos en tests/fixtures; expectativas en
expected.json y precision_cases.py. 25 casos A–E solicitados y cinco casos
adicionales SSRF, plantillas y HTML. Nunca se importa/ejecuta su código.
Grupo F se ejercita desde tests/test_precision.py: sintaxis, tamaño/codificación,
profundidad, nombres Unicode/espacios, binarios e instrucciones maliciosas.

Baseline congelado: tests/baseline_v201.py extraído del motor confiable del commit
51a3abb, sin reimplementar su comportamiento. Código fuente/rules SHA en
[evaluation-results.json](evaluation-results.json). Resultado por fixture incluye
categoría, estados esperados/obtenidos, evidencia, limitaciones y comparación.

```text
python -B tests/evaluate_precision.py --output /ruta/resultado-nuevo.json
python -B -m unittest discover -s tests -v
```

Una alerta legacy es una señal en la categoría esperada; v2.1 cuenta PROBABLE o
CONFIRMED como alerta. FALSE_POSITIVE y NOT_VERIFIED siguen en el informe pero
no se cuentan como vulnerabilidades. Dos casos con verdad desconocida no tienen
etiqueta positiva/negativa: ambos siguen publicados y se evalúa su estado esperado.
No se eliminan para mejorar métricas. Hay 28 casos etiquetados (14 seguros,
14 inseguros) y dos casos inciertos. No hubo explotación reproducida.

| Versión | TP | FP | FN | TN | Precisión | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v2.0.1 | 3 | 3 | 11 | 11 | 50 % | 21,43 % | 30 % |
| v2.1 STANDARD | 14 | 0 | 0 | 14 | 100 % | 100 % | 100 % |

Exactitud de estados: 30/30. Métricas por categoría, lenguaje y framework en JSON.
Estos fixtures guiaron el desarrollo: son pruebas de aceptación, no un benchmark
independiente. El 100 % describe únicamente estos ejemplos. No acredita precisión
general, ausencia de vulnerabilidades ni certificación de frameworks/lenguajes.

## Falsos positivos resueltos en este conjunto

| Caso | Código | v2.0.1 | v2.1 |
| --- | --- | --- | --- |
| A1 | eval("2 + 2") | CWE-95 candidato | FALSE_POSITIVE: expresión aritmética literal |
| A4 | entrada restringida a dos expresiones, else rechaza | CWE-95 candidato | FALSE_POSITIVE: allowlist dominante |
| C14 | comando restringido a date/whoami, else rechaza | CWE-78 candidato | FALSE_POSITIVE: comandos sin metacaracteres |

No se ocultan estas observaciones: se conservan hipótesis, mitigación y transición.
A3 (función sin entrada resuelta) y E25 (middleware externo) quedan NOT_VERIFIED.
No se declara que una función no sea accesible únicamente porque no se ve su caller.

## Casos nuevos identificados

B7/B10: input → concatenación/f-string → cursor.execute: PROBABLE SQL injection.
D16/D18: input → ruta → open: PROBABLE; startswith no prueba confinamiento.
E20/E22/E24: recurso por ID/tenant cliente sin restricción local: PROBABLE, no
explotación confirmada. S1: destino HTTP externo; T1: texto de plantilla externo;
X1: entrada externa marcada como HTML seguro. La versión anterior no señalaba
esas categorías en estos ejemplos. C13 añade investigación de opciones de curl.

## Pruebas fuera de las métricas de fixtures

Regresiones de guards no dominantes, reasignaciones/export previo a autorización,
transformaciones desconocidas, escapes entre contextos, aliases/rebinding,
imports locales, global reads, early returns, correlación DEEP, JWT, máquina de
estados, explotación separada, estabilidad de IDs y límites. Pruebas de CLI en
los tres modos y exportación legacy, que compara campos con el esquema v2.0.1.
El parser aislado se verifica con presupuesto de memoria insuficiente y timeout;
STANDARD y DEEP desde CLI verifican también el Job Object en esta máquina Windows.

Cero FP/FN en estos 28 casos; errores potenciales fuera del corpus en coverage.md.
Validación semántica local del esquema ejecutada; validador externo Draft 2020-12
no instalado en este entorno. Se conserva esquema original para comparación.
