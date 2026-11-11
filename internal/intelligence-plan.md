# v2.1 — Diagnóstico y plan

Base: main `51a3abb390b799a13baceb0cfb922e8786e4d6ac`, árbol limpio.
Rama de trabajo: `feature/intelligence-precision-v2.1`.

## Diagnóstico ejecutado

Python 3.12, Windows. `python -B -m unittest discover -s tests -v`:
36 pruebas, 35 aprobadas, una omitida (creación de symlink sin permisos).
Primera ejecución restringida: errores de acceso a temporales; repetida fuera
del aislamiento, sin cambiar las pruebas. Instalador con cinco perfiles,
fuentes ZIP/padre/directorio, hashes documentales y seguridad de rutas.
CLI scan/report/validate-skill/extract-zip/tools. No existe directorio tools:
la implementación real está en scripts/security_auditor. Los módulos son guías.

AST anterior: búsqueda de llamadas eval/exec, pickle, shell y verify=False;
sin propagación, scopes ni comprobación de controles. HTML JS/TS y secretos
por patrones. JSON 2.0, Markdown y prompt; 21 fases con cobertura explícita.
Scanners externos solo descubiertos, nunca ejecutados. Sin dependencias pip.

## Diseño autorizado por el prompt v2.1

Conservar estructura y APIs; añadir módulos de estados, contexto/flujo Python,
autorización acotada y evaluación. Biblioteca estándar. Separar determinismo
del razonamiento del agente. Mantener campos y schema_version 2.0; extensiones
opcionales. Las máquinas no confirman explotación, ni controles por su nombre.

## Secuencia de implementación y comprobación

1. Fixtures seguros/vulnerables y pruebas de estados antes del motor.
2. Máquina de estados con motivos y requisitos de confirmación verificables.
3. AST Python: fuentes, asignaciones, concatenaciones, controles dominantes,
   sinks y trazas. DEEP: llamadas locales directas acotadas, sin código ejecutado.
4. Modelo Flask/Flask-Login y consultas estructurales de propietario/tenant;
   middleware/desconocidos conservan NOT_VERIFIED.
5. QUICK/STANDARD/DEEP en scan; límites y motivos de cobertura incompleta.
6. Esquema, Markdown, prompts compatibles y pruebas de manipulación de estados.
7. Comparación con python_candidates de v2.0.1 congelado por Git, métricas
   por categoría y ejemplos. No usar números como precisión general.
8. Regresión completa, integridad, CLI, instalación, documentación y diff.

Revisión especial: guards en ramas no dominantes, reasignaciones/import aliases,
funciones validate engañosas, middleware externo y sanitización entre contextos.
Sin commit/push ni modificación de main en esta entrega.
