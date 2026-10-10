# Changelog

## 2.0.1 — 2026-10-10

- Corregida identificación de fuentes descargadas: carpeta de cualquier nombre,
  sufijos `-main`/versión, padre con raíz única y ZIP mediante `--source`.
  Metadatos y metodología verifican identidad; instalación con nombre estándar.
- Fuentes ambiguas/incompletas/enlazadas y ZIP peligrosos se rechazan. El instalador
  usa sus helpers confiables, no importa ni ejecuta código de la fuente ZIP.
- Integridad documental independiente de CRLF/LF y BOM UTF-8. El texto completo
  coincide con Git original `5633241`; hash canónico `904d385…928a`. Se conserva
  el archivo local íntegro; no se actualiza el hash a partir de una coincidencia
  de encabezados. Procedencia y comparación en `docs/corrections-2.0.1.md`.
- Ampliada suite con nombres fuente, padre, ZIP formato GitHub y nombres arbitrarios,
  ambigüedad, enlaces, cambios de texto y no ejecución del ZIP. Probado además el
  ZIP real descargado de GitHub con los cinco perfiles en destinos de prueba.
- Sin cambios de rutas/perfiles, rama `main`, alcance ni 21 fases. Activación
  real de clientes y pruebas nativas Linux/macOS siguen pendientes.

## 2.0.0 — 2026-10-10

- Preservada íntegramente la metodología original de 21 fases y los criterios
  técnicos, asesoría, tipos de hallazgo y prompt del contrato original.
- Metadatos Agent Skills: licencia, requisitos opcionales y versión; OpenAI YAML
  normalizado sin `policy.products` no documentado. Conservada invocación implícita.
- Añadidos motor de triaje estático offline, AST Python y señales de secretos/HTML,
  cobertura explícita, informes Markdown/JSON y prompt de remediación.
- Añadidos límites, rechazo de enlaces/reparse, extracción ZIP portable,
  redacción y validación semántica de hallazgos. Sin ejecución del objetivo.
- Instalador por cinco perfiles documentados, dry-run, integridad SHA256,
  update explícito y desinstalación conservadora con protección de cambios.
- Referencias modulares, guías por dominio y fuentes primarias ampliables.
- Pruebas automatizadas con entradas sintéticas y negativas; no hay credenciales
  reales en fixtures. Integraciones scanner limitadas a descubrimiento/planes.
- Clientes reales y Linux/macOS pendientes de validación; no se promete pentest,
  certificación, sandbox de ejecución ni resistencia empírica de modelos a injection.

## Base anterior

Skill de asesoría para cualquier software, metodología 21 fases, metadatos
OpenAI, icono y licencia MIT. Sin instalador ni código de análisis automatizado.
