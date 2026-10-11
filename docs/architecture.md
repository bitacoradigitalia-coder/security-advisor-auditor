# Arquitectura v2.1

## Diagnóstico y decisiones

Base y pruebas iniciales en intelligence-plan.md. Se conserva scripts/ en lugar
 de crear directorios tools vacíos. El instalador no necesita cambios: incluye
recursivamente scripts/tests/docs/schemas. Sin dependencias pip ni proveedor IA.

Flujo: safeio → inventario/secretos → isolation/worker → contextual/dataflow +
authorization → verification → reporting → JSON/Markdown/prompt.

- engine.py integra modos, cobertura, límites, redacción y IDs deterministas.
- isolation.py inicia únicamente worker.py confiable con `-I -B`, sin importar el
  objetivo; stdin/stdout locales, sin red. Windows: Job Object de memoria de
  proceso y kill-on-close; POSIX: RLIMIT_AS antes de leer la entrada.
- worker.py procesa texto con ast.parse, límite duro de tiempo desde el padre,
  memoria/nodos y resultados truncados. Nunca evalúa expresiones del objetivo.
- dataflow.py representa valores abstractos inmutables: orígenes, trazas,
  incertidumbre, literales, resolución de rutas y controles por contexto.
- contextual.py resuelve asignaciones, concatenaciones, f-strings, guards de
  rechazo dominante, imports/aliases simples y llamadas directas locales en DEEP.
  Un join conserva taint de todas las ramas y solo controles comunes. Una
  transformación desconocida invalida controles, aunque preserve origen.
- authorization.py identifica Flask/Blueprint y Flask-Login, consultas por
  propietario/tenant y rechazo inmediato antes de utilizar un recurso. Un guard
  no protege otro objeto ni una consulta anterior ya exportada/reasignada.
- verification.py aplica máquina de estados con motivos y requisitos de evidencia.
  El validador verifica estructura; un reviewer debe comprobar veracidad.

## Estados y confirmación

CANDIDATE es solo sintaxis. PROBABLE necesita flujo/contexto. FALSE_POSITIVE
necesita mitigación concreta. NOT_VERIFIED explica el bloqueo y conserva evidencia.
CONFIRMED exige reviewer, reachability, control_violation y reproduction. Solo se
llega desde PROBABLE; los cambios quedan registrados en state_history. Para
reabrir un confirmado/falso positivo se vuelve explícitamente a CANDIDATE.

La explotación se registra aparte en verification.exploitation: por defecto
not_tested. confirmed requiere CONFIRMED, local_test, executed=true, resultado,
autorización y aislamiento. Ningún scan automático produce esa confirmación.
No se ha reproducido ningún exploit del objetivo en esta entrega.

## Compatibilidad

Conservar schema_version=2.0 y todos los campos anteriores; añadir campos opcionales
status/category/analyzer/regression_test y evidencias/verificación ampliadas.
Esquema en schemas/audit-report.schema.json y referencia finding.schema.json.
Consumidores estrictos del esquema anterior necesitan actualizarlo o usar
scan --legacy-report. La exportación conserva campos legacy y no muta el informe.
No se promete que el esquema anterior acepte los campos nuevos.

Se mantienen report, Markdown, prompt, fases, controles de ZIP/rutas, cinco
perfiles y hash documental. El workflow anterior que reemplaza verification
para una revisión manual se normaliza con motivo explícito de compatibilidad.
IDs derivados de archivo/función/línea/categoría/CWE (SHA256 truncado de 96 bits
expresado en decimal para conservar el patrón SAA); no son IDs de contenido.

## Límites

Memoria: límite del proceso parser (commit en Windows, espacio virtual en POSIX),
no límite RSS total del CLI; además estimación conservadora bytes×64/nodos×1024.
Timeout duro por parser; inventario cooperativo, límite de entradas 50000,
profundidad y bytes. Git rev-parse tiene su timeout local independiente de 5 s.
Límites alcanzados producen omisiones/truncamientos explícitos. Sin defensa frente
a cambios concurrentes hostiles: usar snapshot aislado. El proceso limita recursos,
no autoriza ni proporciona un entorno para ejecutar código desconocido.
