# security-advisor-auditor

Skill de asesoría y auditoría de seguridad para **cualquier tipo de software**: aplicaciones web, SaaS, APIs, backend, móviles, CLIs, automatizaciones, bibliotecas e infraestructura.

## Qué hace

- Audita repositorios de código: arquitectura, autenticación, autorización, aislamiento de recursos y tenancy, lógica de negocio, tokens y secretos, inyección, concurrencia, abuso/DoS, integraciones, privacidad, clientes (web/móvil/desktop), dependencias y supply chain, CI/CD, contenedores y despliegue.
- Clasifica cada hallazgo: vulnerabilidad confirmada, debilidad probable, riesgo arquitectónico, hardening o informativo, con evidencia verificada.
- Entrega un informe con prioridades y un plan de remediación incremental (antes de producción → corto plazo → arquitectura → escala).
- Genera un prompt copiable y específico para un agente programador con las correcciones.

## Qué no hace

- No edita el código del producto por defecto (modo asesor).
- No sustituye a un pentesting externo ni constituye certificación ni cumplimiento legal.
- No realiza pruebas activas fuera del alcance autorizado.

## Uso

Copia `SKILL.md` y `references/audit-methodology.md` en tu skill y pide una auditoría indicando el repositorio o pegando el código. La metodología (21 fases) se adapta al tipo de producto; las fases no aplicables se justifican explícitamente.

## Estructura

- `SKILL.md` — contrato y flujo de la skill.
- `references/audit-methodology.md` — metodología completa de auditoría.
- `agents/openai.yaml` — configuración de agente para OpenAI.

## Contribuciones

Abierta a contribuciones vía pull requests.
