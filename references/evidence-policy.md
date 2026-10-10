# Política de evidencia

Cada observación conserva ID, fase, archivo y líneas/función, commit si existe,
descripción, precondiciones, evidencia redactada, impacto, severidad justificada,
prioridad, confianza, verificación, remediación y referencias. Un commit no
identifica cambios sin commit: registrar que se revisó el árbol de trabajo.

Tipos originales: `confirmed_vulnerability`, `probable_weakness`,
`architecture_risk`, `hardening`, `informational`. Un elemento no evaluado es
estado de cobertura, no vulnerabilidad. No equiparar confianza con severidad.
Una señal AST/regex inicia investigación; puede ser ejemplo, código muerto,
entrada constante, operación autorizada o dato ya validado.

Para confirmar mediante `static_trace`: revisar entrada, controles y camino
alcanzable hasta el efecto, identidad/tenant, precondiciones y control violado;
registrar reviewer, reachability y control_violation. No requiere ejecutar un
exploit, pero tampoco debe decir «probado» si no se ejecutó. Para `local_test`,
registrar además executed=true, comando autorizado, entorno aislado y resultado.
El validador comprueba campos, no la veracidad de las afirmaciones del reviewer.

Cobertura: `not_evaluated`, `automated_partial`, `reviewed`, `not_applicable`.
Todas las 21 fases deben estar presentes con razón. No aplicable requiere una
justificación contextual; no se deriva solo de ausencia de un archivo.

No asignar CVE propio. El esquema base no admite CVE/CVSS: adjuntar advisories
oficiales y evaluaciones justificadas como referencias, verificadas con fecha.
Nunca afirmar ausencia de vulnerabilidades a partir de cero coincidencias.
No arrastrar hallazgos entre versiones sin verificarlos de nuevo.
