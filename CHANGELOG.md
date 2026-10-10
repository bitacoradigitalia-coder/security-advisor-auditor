# Changelog

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
