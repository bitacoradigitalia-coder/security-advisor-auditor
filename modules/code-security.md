# Código y clientes no web — fases 2–5, 7–9, 13–14, 16

Trazar entrada → validación → autorización → efecto. Revisar CLI args, paths,
entorno, deserialización, shell y límites de recursos. El motor AST detecta
eval/exec, pickle, os.system/popen, subprocess con shell=True y verify=False
en requests/httpx, incluso aliases simples. No sigue flujos, scopes ni aliases
dinámicos; rebinding puede generar falsos positivos. Revisar manualmente.

Separar controles de rol, propiedad y tenant de validación de datos. Identificar
entradas constantes, sinks seguros y comprobaciones previas antes de confirmar.
Para móvil/desktop, no confiar en almacenamiento ni permisos del dispositivo;
backend conserva autorización. No exportar secretos a logs/analytics.
Fuente: [CWE](https://cwe.mitre.org/). Revisar fases originales por título.
