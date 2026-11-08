# PLAN v2.3 — Mejoras 11-20 (roadmap maestro)

> **Documento de continuidad.** Cualquier IA o desarrollador puede retomar la construcción desde aquí.
> Regla: al completar cada PASO, marcar su checkbox (`- [x]`), actualizar el campo **Estado** de la mejora
> y hacer commit ("plan: M## paso N completado"). Al completar una MEJORA entera, cerrar su issue,
> actualizar CHANGELOG y guardar checkpoint en el conocimiento persistente (ver Protocolo).

## Estado global
- CI: pytest BLOQUEANTE + mypy BLOQUEANTE (0 errores) en `ci-tests.yml`. Los dos deben seguir en verde tras cada paso.
- Base actual: v2.2.0-alpha (tag d1e7ffd). Fases 1-5 + mejoras 1-10 completadas.
- Mejoras e issues: M11 ✅ (#5) | M12 ✅ (#6) | M13 ⏳ (#7) | M14 ⏳ (#8) | M15 ⏳ (#9) | M16 ⏳ (#10) | M17 ⏳ (#11) | M18 ⏳ (#12) | M19 ⏳ (#13) | M20 ⏳ (#14)

---

## Protocolo de continuidad (OBLIGATORIO para cualquier IA)

1. **Leer primero**: este archivo, `CHANGELOG.md` y el checkpoint más reciente del conocimiento persistente (archivo de progreso en /home/user/knowledge/security-advisor-auditor/).
2. **Checkpoints**: tras CADA paso completado, guardar checkpoint en el archivo de progreso del conocimiento (append, nunca reescribir). Si el crédito se agota a mitad de una mejora, el checkpoint debe permitir reanudar sin repetir trabajo.
3. **Commits**: uno por paso (o pocos pasos coherentes). Verificar CI verde tras cada uno (la página de Actions muestra el estado ANTES de la entrada del run; ojo, el estado precede a la línea).
4. **Tests**: cada mejora añade tests en `tests/`. Sin tests no se considera terminada.
5. **Mypy**: los archivos de `scripts/core` deben quedar a 0 errores (mypy.ini strict). mypy es bloqueante en CI.

### Técnicas validadas en este repo (leer antes de tocar código)
- `get_file_contents` (github_app) NO devuelve texto usable in-script: el texto EXACTO llega en el MSLResource adjunto al tool result (~32.8k máx).
- `push_files` es SEGURO para archivos completos, incluidos backslashes de regex, SI el contenido se construye con template literal `String.raw` en run_typescript (un template normal CORROMPE los escapes de regex). Si el archivo contiene backticks, usar template normal con backtick escapado (y entonces no puede contener backslashes).
- Verificación de transcripción: usar números de línea conocidos como anclas (content.split con nueva línea, línea n-1 recortada debe coincidir con la línea esperada) ANTES de pushear.
- `open_url` sobre raw.githubusercontent ENVUELVE líneas y trunca a ~32.8k: NUNCA re-subir contenido leído así.
- `create_or_update_file` corrompe contenido: no usar.
- Diagnóstico de CI que FUNCIONA: paso en el workflow (con permissions contents write) que sube logs a una rama `ci-diag` vía curl PUT a la API contents con secrets.GITHUB_TOKEN (el push git desde el runner falla silenciosamente); luego leer con get_file_contents ref ci-diag. ELIMINAR el paso de diagnóstico al terminar. El nombre del archivo de log debe usar `${{ github.run_id }}` (coincide con el id de la API de runs).
- Doble import `core.X` vs `scripts.core.X`: `scripts/` es namespace package, ambos cargan como módulos DISTINTOS y sus enums/clases NO son comparables (== falla aunque el repr sea idéntico). Los módulos de scripts deben preferir `core.*` en el try (fallback `scripts.core.*`) para alinearse con los tests.
- `pytest | tee log` MASCARA el exit code de pytest (devuelve el de tee): nunca usarlo como paso bloqueante.
- YAML de workflows: nunca step name con ": " sin comillas; nunca heredocs con cuerpo a indentación 0 (usar scripts auxiliares como `scripts/bugbounty/ci_actions.py`).
- El laboratorio de pruebas es `tests/lab/vulnerable_app.py` (127.0.0.1, stdlib solo) y el conector GitHub NO expone crear tags/releases (manual).

---

## M11 — Servidor OOB para vulnerabilidades ciegas (SSRF/XXE/RCE blind)
**Estado: ✅ completada (2026-11-08, CI #73 verde) | Issue: #5 cerrado | Prioridad: ALTA (hueco funcional mayor)**

Objetivo: confirmar vulnerabilidades ciegas con canal de retorno (estilo interactsh), integrado con el modelo de confianza (evidencia de callback → CONFIRMED).

- [x] 11.1 `scripts/core/oob.py`: `OOBServer` (HTTP listener en 127.0.0.1 puerto efímero con stdlib http.server, registro de callbacks con timestamp + payload-id, thread-safe, context manager) y `OOBClient` (polling con timeout, fetch inyectado para servidor remoto interactsh-like). Interfaz agnóstica (`new_interaction`/`url_for`/`wait_for_callback`).
- [x] 11.2 **Desviación documentada**: en vez de integrar en `Fuzzer` (re-transcribir ~1000 líneas con riesgo de corrupción), se creó `scripts/pentesting/oob_scanner.py` (`OOBScanner`) con payloads ciegos SSRF/XXE/RCE parametrizados con interaction_id único, validación de scope/engagement y `probe_parameter()`. Equivalente funcional; la integración en Fuzzer queda como mejora futura opcional.
- [x] 11.3 Integración con `EvidenceEngine`: al detectarse callback, evidencia REQUEST (interacción) + evidencia LOG (callback) y hallazgo a VerificationStatus.CONFIRMED / ConfidenceLevel.CONFIRMED vía `set_verification_status`.
- [x] 11.4 Laboratorio extendido: `/fetch?url=` con `urllib.request.urlopen` sin validación (SSRF ciego) en `tests/lab/vulnerable_app.py`, tests existentes intactos.
- [x] 11.5 Tests (`tests/test_oob.py`): registro y aislamiento por interaction_id, OOBClient con fetch inyectado, E2E SSRF ciego CONFIRMED (≥2 evidencias) y sonda negativa sin callback (order-independientes). Fix de CI: los tests NO pueden asumir orden alfabético de unittest, y el scanner prefiere `core.*` en el import dual (evita enums no comparables por doble módulo).
- [x] 11.6 CI verde (#73: 208 passed, 2 skipped) + CHANGELOG + checkpoint. Estado M11 → ✅.

## M12 — SCA / SBOM con advisory matching (OSV)
**Estado: ✅ completada (2026-11-08, CI #75 verde) | Issue: #6 cerrado | Prioridad: ALTA**

- [x] 12.1 `scripts/sca/sbom.py`: SBOM CycloneDX 1.5 (JSON) desde `requirements.txt` (`parse_requirements` + `SBOMGenerator`, determinista, sin timestamps). FASE 3 dejó requirements.txt ya auditado (solo requests y pyyaml): ese es el inventario reutilizado.
- [x] 12.2 `scripts/sca/osv_client.py`: `OSVClient` OFFLINE por defecto con caché local versionada `scripts/sca/advisories.json` (seeds reales: GHSA-jpzg-p363-qq3p / CVE-2023-32681 requests<2.31.0); modo online OPT-IN (`online`/`--online`) contra api.osv.dev con validación de ScopeManager.
- [x] 12.3 `scripts/sca/scanner.py` (`SCAScanner`): advisory → finding CONFIRMED del EvidenceEngine (severidad del advisory, CWE, fix en la descripción y en evidencia LOG). **Desviación documentada**: la pasada por `AIEngine` para priorización queda diferida (los findings ya llevan severidad y fix; integración puntual cuando se unifique el pipeline de findings).
- [x] 12.4 **Desviación documentada**: CLI propia `python scripts/sca/cli.py --requirements requirements.txt --output ./sca-report [--online]` en vez de subcomando en `scripts/audit.py` (~900 líneas con f-strings anidados; el riesgo de re-transcripción supera el beneficio). Genera sbom.json + sca-report.json.
- [x] 12.5 Tests (`tests/test_sca.py` con fixture `tests/fixtures/sca/requirements.txt`): SBOM válido en campos mínimos, matching offline determinista, versión parcheada no afectada, paquete limpio sin hallazgos, hallazgo con fix sugerido y evidencia.
- [x] 12.6 CI verde (#75) + CHANGELOG + checkpoint. Estado M12 → ✅.

## M13 — Escaneo IaC y CI/CD (Dockerfile, compose, K8s, Terraform, GitHub Actions)
**Estado: ⏳ pendiente | Issue: #7 | Prioridad: ALTA (el propio repo tiene workflows)**

- [ ] 13.1 `scripts/static_analysis/iac_analyzer.py` (`IaCAnalyzer`, TOOL_NAME="iac_native") reutilizando `RuleEngine`. Reglas:
  - Dockerfile: DOCK001 root USER, DOCK002 secrets en ENV/RUN, DOCK003 ADD de URL, DOCK004 tag :latest
  - docker-compose / K8s: K8S001 privileged true, K8S002 hostPort/hostNetwork, K8S003 runAsNonRoot ausente, K8S004 capabilities ADD
  - Terraform: TF001 security group 0.0.0.0/0, TF002 bucket sin encryption, TF003 recursos públicos
  - GitHub Actions: GHA001 pull_request_target con checkout de head, GHA002 inyección de expresiones de evento en bloques run, GHA003 permissions amplios, GHA004 secrets volcadas a env
- [ ] 13.2 Registrar en `static_analysis/__init__.py` (analyze_directory por extensión: Dockerfile, .yml/.yaml, .tf, .hcl).
- [ ] 13.3 Auto-auditoría: el propio repo debe pasar limpio o con hallazgos justificados (dogfooding; documentar en `docs/iac.md`).
- [ ] 13.4 Tests (`tests/test_iac_analyzer.py`): al menos 1 test por familia, 0 falsos positivos en fixtures limpios.
- [ ] 13.5 CI verde + CHANGELOG + checkpoint. Estado M13 → ✅.

## M14 — Verificación de XSS en DOM con navegador headless (Playwright opcional)
**Estado: ⏳ pendiente | Issue: #8 | Prioridad: MEDIA**

- [ ] 14.1 `scripts/pentesting/dom_verify.py`: `DOMVerifier` que usa Playwright SOLO si está instalado (patrón Nuclei: verify con playwright_path None); sin Playwright → devuelve estado PROBABLE actual sin romper nada.
- [ ] 14.2 Verificación real: inyectar payload canónico con ID único, navegar, escuchar el evento → CONFIRMED + EvidenceType.SCREENSHOT (tipo ya definido y sin usar en EvidenceEngine).
- [ ] 14.3 Integrar en `scanner.py` tras detección de reflexión XSS (solo con flag `--dom-verify`).
- [ ] 14.4 Extender laboratorio con endpoint de reflexión (si no existe) y tests: skipped si Playwright no está (pytest.mark.skipif), end-to-end si lo está.
- [ ] 14.5 CI verde (tests deben pasar sin Playwright instalado) + CHANGELOG + checkpoint. Estado M14 → ✅.

## M15 — Diferencial IDOR / BOLA multi-sesión
**Estado: ⏳ pendiente | Issue: #9 | Prioridad: ALTA (rentabilidad pentest)**

- [ ] 15.1 `scripts/pentesting/differential.py`: `DifferentialTester` que re-ejecuta una petición con 2 sesiones del `AuthManager` (admin vs usuario normal) y compara: status, content-length, JSON structural diff (claves añadidas/eliminadas), campos sensibles.
- [ ] 15.2 Heurística de hallazgo: mismo endpoint devuelve datos de otro usuario o divergencia 200-vs-403 → finding IDOR con evidencia par (las dos respuestas, secretos redactados por EvidenceEngine).
- [ ] 15.3 Todo el tráfico SIEMPRE vía ScopeManager y solo con engagement activo (EngagementManager) — es operación activa.
- [ ] 15.4 Laboratorio: añadir /api/users/<id> vulnerable (devuelve datos sin comprobar propietario) + sesiones user/admin.
- [ ] 15.5 Tests (`tests/test_differential.py`): IDOR detectado end-to-end, control negativo (endpoint que sí comprueba), divergencia explicada en la evidencia.
- [ ] 15.6 CI verde + CHANGELOG + checkpoint. Estado M15 → ✅.

## M16 — Exportación SARIF + calculadora CVSS 3.1
**Estado: ⏳ pendiente | Issue: #10 | Prioridad: MEDIA**

- [ ] 16.1 `scripts/reporting/sarif.py`: exporter SARIF 2.1.0 (results con ruleId, level, location, cwe en properties) desde los hallazgos del análisis estático.
- [ ] 16.2 Workflow: upload del SARIF con la action oficial de GitHub (upload-sarif) con permiso security-events write, tolerante (el SARIF se genera también como artifact).
- [ ] 16.3 `scripts/core/cvss.py`: calculadora CVSS 3.1 (vector completo + base score; guardar el VECTOR como evidencia junto al score en el finding).
- [ ] 16.4 Tests: SARIF válido en campos mínimos, calculadora con vectores oficiales de ejemplo del estándar (score esperado conocido).
- [ ] 16.5 CI verde + CHANGELOG + checkpoint. Estado M16 → ✅.

## M17 — Mapeo OWASP Top 10 (2021) + ASVS 4.0 por hallazgo
**Estado: ⏳ pendiente | Issue: #11 | Prioridad: MEDIA**

- [ ] 17.1 `references/owasp-mapping.json`: mapa CWE → OWASP Top 10 2021 (A01-A10) → puntos ASVS 4.0 relevantes (versionado, auditable, con fuente).
- [ ] 17.2 Enriquecer Finding con campos `owasp_category` y `asvs_references` (dataclass retrocompatible con from_dict/to_dict).
- [ ] 17.3 `ProfessionalReporter`: nuevo informe "por control" (severidad agregada por categoría OWASP + coverage de ASVS probado vs no probado).
- [ ] 17.4 Tests: mapeo completo para los CWE ya usados por las reglas existentes, informe generado sin romper los formatos actuales.
- [ ] 17.5 CI verde + CHANGELOG + checkpoint. Estado M17 → ✅.

## M18 — Descubrimiento de endpoints desde bundles JS
**Estado: ⏳ pendiente | Issue: #12 | Prioridad: MEDIA**

- [ ] 18.1 `scripts/pentesting/js_harvest.py`: extraer rutas de archivos .js y .js.map (regex de rutas, source maps: parsear sources y sourcesContent), deduplicar, normalizar contra el host del scope.
- [ ] 18.2 Alimentar `ActiveScanner` (nuevos candidate paths) y `Fuzzer` (endpoints con parámetros detectados por nombres en el bundle).
- [ ] 18.3 Detección de source maps expuestos como hallazgo propio (information disclosure).
- [ ] 18.4 Tests con fixtures (`tests/fixtures/js_bundle/` con bundle sintético + .map): rutas extraídas, rutas fuera de dominio rechazadas (validación contra ScopeManager).
- [ ] 18.5 CI verde + CHANGELOG + checkpoint. Estado M18 → ✅.

## M19 — Sello de evidencias con hash encadenado (defensabilidad)
**Estado: ⏳ pendiente | Issue: #13 | Prioridad: BAJA (diferencial de producto)**

- [ ] 19.1 `scripts/core/evidence_chain.py`: al persistir cada evidencia, calcular sha256(prev_hash + evidence_json canónico) y guardar `chain_hash`; génesis documentada.
- [ ] 19.2 `verify_chain()`: recorre el storage y reporta evidencias alteradas o fuera de orden.
- [ ] 19.3 CLI: `python scripts/audit.py verify-evidence <storage>` y mención del hash en el reporte.
- [ ] 19.4 Tests: cadena válida pasa, evidencia manipulada rompe exactamente en su posición, orden alterado detectado.
- [ ] 19.5 CI verde + CHANGELOG + checkpoint. Estado M19 → ✅.

## M20 — Threat modeling ligero (STRIDE)
**Estado: ⏳ pendiente | Issue: #14 | Prioridad: BAJA**

- [ ] 20.1 `scripts/threat_model/stride.py`: inventario de componentes del objetivo (manifiestos/infra: BD, cola, storage, API, frontend) y generación de candidatos STRIDE por tipo de componente (tabla de heurísticas versionada).
- [ ] 20.2 Cada amenaza candidata → check concreto: mapear a reglas del static analyzer y a módulos del escáner activo (loop cerrado "qué debería preocuparme" → "qué he testeado").
- [ ] 20.3 Reporte de brechas: amenazas sin check disponible → limitación documentada.
- [ ] 20.4 Tests con fixture de manifiesto (docker-compose sintético): componentes detectados, amenazas mínimas, checks sugeridos resolubles.
- [ ] 20.5 CI verde + CHANGELOG + checkpoint. Estado M20 → ✅.

---

## Orden recomendado y dependencias
M11 → M12 → M13 → M15 → M18 → M14 → M16 → M17 → M19 → M20.
M11/M12/M13/M15 son las de mayor impacto con la arquitectura actual. M14 requiere Playwright (tests skip sin él). M17 conviene antes de M16 si el SARIF debe llevar categoría OWASP (decidir en 16.1). M19/M20 son autónomos.

## Definición de terminado (cada mejora)
1. Tests nuevos pasando + CI verde (pytest y mypy bloqueantes).
2. Este plan actualizado (checkboxes + Estado) y commit.
3. CHANGELOG con la mejora.
4. Checkpoint guardado en el conocimiento persistente (archivo de progreso), con commits, runs de CI y cualquier técnica nueva aprendida.
5. Issue de la mejora cerrado.
