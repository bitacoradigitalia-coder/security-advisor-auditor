# Roadmap

Estado contrastado con el código de la rama base `e60ec8c` (11 de noviembre de 2026). La existencia de un módulo no acredita su integración en todos los comandos ni que esté listo para producción. Los resultados vigentes de pruebas se consultan en [CI](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/actions/workflows/ci-tests.yml).

## Disponible y límites actuales

| Área | Entrada disponible | Límite |
|---|---|---|
| Escaneo estático | `audit.py scan CARPETA --output DESTINO` | Motor `security_auditor`; no integra todos los analizadores nuevos |
| Pentesting | `scan --active`, `scan --fuzz`, `fuzz`, `idor` | Requiere autorización y alcance; revisión de controles pendiente en otros clientes HTTP |
| SCA | `scripts/sca/cli.py` | CLI independiente; caché offline limitada; OSV online opcional |
| IaC | API Python `IaCAnalyzer` | Sin subcomando `audit.py iac` |
| OOB | API Python en `core/oob.py` y `pentesting/oob_scanner.py` | Sin subcomando `audit.py oob` |
| Reportes | `audit.py report`, `cvss`, `poc` | Compatibilidad dependiente del esquema y tipo de hallazgo |
| AI Defense | `audit.py ai-defense` | Patrones y heurísticas; no demuestra detección zero-day |

Los ejemplos compatibles con el parser están en [Uso](usage.md) y los argumentos en [CLI](cli.md). Los planes y cierres anteriores se conservan en [internal](../internal/) y [history](history/).

## Próximos pasos, en orden

1. **Consolidar el núcleo**: alcance y autorizaciones en cada cliente HTTP, validación de redirecciones antes de enviarlas, errores explícitos, pruebas de regresión y esquemas de reportes consistentes.
2. **Unificar el escaneo de repositorios**: integrar explícitamente los analizadores de lenguajes, SCA e IaC; informar cuáles se ejecutaron, sus errores y archivos omitidos.
3. **Aplicación local con botón de escaneo**: selector de carpeta/ZIP, inicio/cancelación, progreso e informe. Primero análisis estático sin ejecutar los archivos descargados.
4. **Dashboard y API REST**: autenticación, trabajos en segundo plano, persistencia y alertas. El uso local no necesita dominio; la exposición remota requiere su propio diseño de seguridad.
5. **Integraciones defensivas**: Cloudflare, ModSecurity, SIEM y Hermes tras verificar contratos reales de sus APIs. Bloqueos con simulación, trazabilidad y reversión.
6. **Análisis avanzado**: GraphQL, Shadow APIs, tráfico, reputación de IP, sandbox, honeypot e integración opcional con LLM. Evaluar cada módulo por separado con datos y límites medibles.
7. **Distribución y monetización**: empaquetado, actualizaciones, licencias comerciales y pagos después de estabilizar el producto.

## Pendiente de demostrar

- [ ] Detección de anomalías + threat intelligence con evaluación reproducible. No etiquetar como «zero-day completado» solo por añadir heurísticas.
- [ ] Aplicación gráfica y flujo completo de escaneo mediante botón.
- [ ] Alertas en tiempo real e integraciones operativas con WAF/SIEM/Hermes.
- [ ] Remediación automática con autorización, simulación y rollback.
- [ ] Informes de cumplimiento con criterios y evidencias verificables.

No se fijan fechas de entrega hasta dimensionar cada bloque. Cada cierre debe enlazar su commit, pruebas ejecutadas y limitaciones pendientes. Los contadores de tests históricos no sustituyen una ejecución actual.
