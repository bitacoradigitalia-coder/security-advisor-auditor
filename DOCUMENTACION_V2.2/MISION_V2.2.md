# 🎯 MISIÓN: EVOLUCIONAR SECURITY ADVISOR AUDITOR A LA VERSIÓN 2.2

**Fecha de creación:** 2026-11-02  
**Versión base:** v2.1.1  
**Objetivo:** Documento de referencia para el desarrollo de v2.2  
**Estado:** Activo

---

## 📌 CONTEXTO

**Actúa como:** Arquitecto de software senior especializado en:
- Python
- AppSec (Application Security)
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)
- Pentesting autorizado
- Análisis de vulnerabilidades
- Seguridad de herramientas de auditoría
- Diseño de sistemas de agentes IA

**Misión:** Auditar, corregir y mejorar el proyecto existente **Security Advisor Auditor**, conservando su arquitectura modular y todas las funcionalidades que ya funcionan.

---

## ⚠️ REGLAS OBLIGATORIAS

### Antes de modificar código:

1. ✅ **Inspeccionar el repositorio completo**
   - Revisar todos los archivos, no solo los principales
   - Entender la estructura y relaciones entre módulos

2. ✅ **Leer toda la documentación**
   - README.md
   - Documentación en `/docs/`
   - Configuraciones (requirements.txt, etc.)
   - Todos los tests

3. ✅ **Identificar la arquitectura**
   - Módulos existentes
   - Interfaces públicas
   - Dependencias entre componentes

4. ✅ **Localizar problemas reales**
   - Reproducir los problemas que sean reproducibles
   - Distinguir entre:
     - Vulnerabilidades confirmadas
     - Riesgos potenciales
     - Mejoras recomendadas

5. ✅ **Crear un plan de implementación**
   - Por fases
   - Con criterios de aceptación claros
   - Priorizado

6. ✅ **Conservar compatibilidad**
   - No eliminar funcionalidades sin justificación técnica
   - Mantener interfaces públicas existentes
   - Proporcionar alternativas compatibles

### Prohibiciones:

- ❌ **No reescribir el proyecto desde cero**
- ❌ **No inventar funcionalidades** (demostrar con código y pruebas)
- ❌ **No ocultar errores** con:
  - Excepciones genéricas
  - Falsos positivos
  - Resultados simulados

---

## 🔴 PRIORIDAD CRÍTICA: SEGURIDAD DEL PROPIO AUDITOR

### 2.1. Control centralizado de alcance (Scope Manager)

**Objetivo:** Implementar un componente centralizado que controle **TODAS** las conexiones de red.

**Requisitos:**
- ✅ Permitir **únicamente** dominios, IP, puertos, protocolos y rutas **expresamente autorizados**
- ✅ Validar el destino **antes de cada petición**
- ✅ Validar **cada redirección HTTP** antes de seguirla
- ✅ Desactivar redirecciones automáticas si impiden verificar el destino
- ✅ Bloquear por defecto destinos **no autorizados**
- ✅ Evitar accesos accidentales a:
  - localhost (127.0.0.1, ::1)
  - Redes privadas (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Link-local (169.254.0.0/16)
  - Endpoints de metadatos cloud (169.254.169.254)
  - **Salvo autorización explícita + validación adicional**
- ✅ Resolver y validar DNS **de forma segura** (evitar DNS rebinding)
- ✅ **Ningún módulo** (fuzzer, scanner, auth, etc.) puede saltarse el control
- ✅ Incorporar límites de:
  - Peticiones por segundo
  - Concurrencia máxima
  - Tiempo máximo por petición
  - Tamaño máximo de respuesta
- ✅ **Kill switch** para detener operaciones activas inmediatamente

**Regla clave:** Centralizar la lógica. **No implementar validaciones independientes en cada módulo.**

---

### 2.2. Protección de credenciales y sesiones

**Foco:** Revisar especialmente `scripts/pentesting/auth.py`

**Requisitos:**
- ✅ Almacenamiento seguro mediante **keyring del SO** (cuando esté disponible)
- ✅ Cifrado de credenciales persistidas (cuando keyring no esté disponible)
- ✅ **Nunca** almacenar contraseñas en texto claro
- ✅ Permisos **restrictivos** en archivos y directorios (ej: 600)
- ✅ Protección frente a:
  - Enlaces simbólicos (symlinks)
  - Condiciones de carrera (race conditions)
- ✅ Caducidad de sesiones (TTL)
- ✅ Revocación y eliminación **segura** de credenciales
- ✅ Redacción **automática** de:
  - Tokens
  - Cookies
  - Contraseñas
  - Secretos
  - **En:** logs, informes, excepciones, trazas, mensajes de depuración
- ✅ **Nunca** mostrar secretos en:
  - Excepciones
  - Trazas de depuración
  - Mensajes de error

**Regla clave:** Si no existe almacén seguro disponible, **fallar de forma segura** o solicitar alternativa explícita. **No recurrir silenciosamente al almacenamiento en texto claro.**

---

### 2.3. Autorización de operaciones de pentesting

**Foco:** Revisar `scripts/pentesting/exploit.py` y todos los módulos con acciones activas.

**Objetivo:** Implementar un **modelo de autorización por engagement**.

**Cada autorización debe incluir:**
- Identificador del engagement (UUID)
- Propietario o responsable (email/nombre)
- Objetivos autorizados (lista exacta)
- Dominios e IP permitidos (lista exacta o patrones seguros)
- Puertos y rutas autorizados
- Tipos de pruebas permitidos (ej: ['sqli', 'xss', 'scan'])
- Fecha y hora de inicio (con zona horaria)
- Fecha y hora de finalización (con zona horaria)
- Límites de velocidad y concurrencia
- Restricciones específicas (ej: "no tocar /admin")
- Evidencia de autorización (archivo, hash, firma)

**Requisitos:**
- ✅ Comprobar la autorización **antes de CADA operación activa**
  - **No solo al iniciar el módulo**
- ✅ Corregir problemas de comparación de patrones wildcard:
  - Escapar caracteres especiales
  - Usar comparaciones estructuradas de dominios/IP/rutas
- ✅ **No permitir** que una autorización para un dominio se interprete como autorización para dominios similares
  - Ejemplo: `example.com` ≠ `notexample.com`
- ✅ Denegar autorizaciones:
  - Caducadas
  - Ambiguas
  - Inválidas
  - Incompletas
- ✅ **No implementar:**
  - Explotación destructiva
  - Persistencia
  - Evasión
  - Acciones fuera del alcance autorizado

---

## 🟠 PRIORIDAD ALTA: PRECISIÓN DEL DETECTOR

### 3.1. Mejorar el motor de verificación

**Problema:** El auditor NO debe clasificar una vulnerabilidad como **CONFIRMADA** únicamente por:
- Respuesta HTTP 500
- Una cadena enviada aparezca reflejada
- El servidor tarde más de lo habitual
- Se produzca una respuesta diferente
- Una expresión regular encuentre una palabra sospechosa

**Solución:** Implementar un **sistema de evidencias** que incluya:
- Solicitud y respuesta relevantes (**con secretos redactados**)
- Parámetro afectado
- Ubicación exacta del hallazgo (archivo:línea o URL+parámetro)
- Payload utilizado
- Comportamiento esperado
- Comportamiento observado
- Evidencia de control y comparación
- Reproducibilidad (pasos para repetir)
- Confianza (low/medium/high/confirmed) + justificación
- Limitaciones (qué no se pudo verificar)
- Referencias técnicas aplicables

**Técnicas para reducir falsos positivos:**
- Pruebas de control **positivas y negativas**
- Diferencias entre respuestas
- Normalización de datos
- Repetición controlada
- Correlación de resultados

---

### 3.2. Estados de vulnerabilidad

**Estados existentes (conservar):**
- `CANDIDATE` → Señal estática sin contexto
- `PROBABLE` → Con contexto o flujo inseguro
- `CONFIRMED` → Vulnerabilidad demostrada y revisada
- `FALSE_POSITIVE` → Hipótesis invalidada localmente
- `NOT_VERIFIED` → Información insuficiente

**Requisitos:**
- ✅ Definir **reglas verificables** para cada transición
- ✅ **No permitir** que un modelo de IA convierta `CANDIDATE` → `CONFIRMED` **sin evidencia técnica independiente**
- ✅ La IA puede:
  - Ayudar a interpretar resultados
  - Proponer verificaciones
  - Sugerir prioridades
  - **Pero NO decidir**
- ✅ La confirmación debe depender de:
  - Evidencias reproducibles
  - Reglas verificables
  - Revisión humana (opcional pero recomendada)

---

### 3.3. Mejoras específicas del fuzzer

**Foco:** Revisar `scripts/pentesting/fuzzer.py`

**Para cada tipo de vulnerabilidad (SQLi, XSS, SSRF, RCE, LFI, IDOR, XXE):**
1. Definir **qué comportamiento constituye una señal** (ej: para SQLi, error de sintaxis SQL en la respuesta)
2. Implementar **comprobación de control** (¿qué pasa con un payload inocuo?)
3. Reducir coincidencias basadas **únicamente en errores genéricos** (ej: 500 Internal Server Error)
4. Guardar **evidencias reproducibles** (request + response)
5. Asignar **nivel de confianza justificado** (low/medium/high/confirmed)
6. Distinguir entre:
   - **Detección heurística** (señal débil)
   - **Confirmación** (evidencia fuerte)

**Regla clave:** Todas las pruebas deben respetar el **Scope Manager** y el **perfil de autorización**.

---

## 🟡 PRIORIDAD MEDIA: CADENA DE SUMINISTRO

**Foco:** Revisar `requirements.txt` y todos los archivos de configuración de dependencias.

**Problemas identificados:**
```txt
session>=0.0.0    # ❌ Versión sin límite, paquete genérico
cookies>=0.0.0    # ❌ No se usa en el código (verificar)
```

**Acciones:**
- ✅ **Eliminar** dependencias innecesarias
- ✅ **Fijar versiones** verificadas (ej: `requests==2.31.0`)
- ✅ Generar archivo de **bloqueo reproducible** (ej: `requirements.lock`)
- ✅ Comprobar vulnerabilidades conocidas con:
  - `safety check`
  - `bandit`
  - `pip-audit`
- ✅ Documentar:
  - Dependencias directas
  - Dependencias transitivas (usar `pipdeptree`)
- ✅ Evitar instalar paquetes **no verificados**
- ✅ Añadir **comprobaciones de integridad** (hashes) cuando el gestor lo permita

**Nota:** No asumir que las dependencias son maliciosas. **Verificar su procedencia, propósito, mantenedor y uso real en el código.**

---

## 🟢 PRIORIDAD MEDIA: ANÁLISIS MULTILENGUAJE

**Objetivo:** Conservar el analizador Python existente y extender a otros lenguajes.

**Arquitectura propuesta:**
- Analizadores **independientes** para cada lenguaje
- Interfaz común para todos los analizadores
- Soporte para:
  - Python (✅ ya existe)
  - JavaScript
  - TypeScript
  - Java
  - PHP
  - Go
  - Rust

**Requisitos:**
- ✅ **No afirmar** que un lenguaje está soportado hasta que exista:
  - Un analizador **funcional**
  - Con **pruebas**
- ✅ Usar **AST** (Árbol de Sintaxis Abstracta) cuando sea apropiado
- ✅ Considerar **Tree-sitter** para análisis avanzado
- ✅ Reglas **especializadas** para cada lenguaje

**Implementación gradual:**
1. Identificación de **fuentes de datos no confiables** (ej: `request.GET`, `user_input`)
2. Seguimiento de **propagación de datos** (taint tracking)
3. Identificación de **sinks peligrosos** (ej: `eval()`, `execute()`, `render_template`)
4. Contexto de **sanitización** (¿se limpia el dato antes de usarlo?)
5. Análisis **interprocedimental** (cuando sea viable)
6. Detección de **configuraciones inseguras**

**Regla clave:** **No sacrificar precisión** para aumentar artificialmente el número de hallazgos.

---

## 🏗️ ARQUITECTURA OBJETIVO (v2.2)

**Componentes principales (desacoplados):**

1. **Orchestrator** → Coordina los módulos
2. **Engagement Manager** → Administra autorizaciones y alcance
3. **Scope Manager** → Controla las operaciones de red
4. **Static Analysis Engine** → Análisis estático (SAST)
5. **Dynamic Analysis Engine** → Pruebas dinámicas autorizadas (DAST)
6. **Supply Chain Analyzer** → Auditoría de dependencias
7. **Evidence Engine** → Recopila y normaliza evidencias
8. **Verification Engine** → Valida los hallazgos
9. **AI Reasoning Engine** → Interpreta resultados y recomienda correcciones
10. **Report Generator** → Produce informes profesionales

**Requisitos de arquitectura:**
- ✅ Componentes **desacoplados**
- ✅ Interfaces **documentadas**
- ✅ La ausencia de un módulo opcional **no debe romper** el funcionamiento del resto

---

## 📄 INFORMES PROFESIONALES

**Cada hallazgo debe incluir:**
- ID único (ej: `SAA-0001`)
- Nombre (ej: "SQL Injection en /login")
- Severidad (critical/high/medium/low/informational)
- Confianza (low/medium/high/confirmed)
- Estado de verificación (`not_verified`, `static_trace`, `local_test`)
- CWE (cuando corresponda, ej: `CWE-89` para SQLi)
- CVSS (cuando exista información suficiente)
- Ubicación:
  - Archivo y línea (para código)
  - URL y parámetro (para webs)
- Descripción técnica
- Impacto (qué podría pasar)
- Evidencias (request/response, payload, etc.)
- Pasos de reproducción **seguros**
- Recomendación de corrección
- Referencias (enlaces a documentación)
- Limitaciones de la comprobación

**Regla clave:** **No inventar** CVE, CWE, CVSS ni referencias.

**Formatos de exportación:**
- JSON (para integración con otras herramientas)
- HTML (para informes visuales)
- Markdown (para documentación)
- **Siempre conservar** la trazabilidad de las evidencias

---

## 🧪 TESTS Y VALIDACIÓN

**Ampliar pruebas automatizadas para:**
- ✅ Validación del alcance (Scope Manager)
- ✅ Redirecciones fuera del alcance
- ✅ Resolución DNS y direcciones no permitidas
- ✅ Protección de credenciales
- ✅ Caducidad de autorizaciones
- ✅ Wildcards y dominios similares
- ✅ Límites de peticiones
- ✅ Kill switch
- ✅ Falsos positivos
- ✅ Falsos negativos
- ✅ Estados de verificación
- ✅ Evidencias
- ✅ Regresión de funcionalidades existentes

**Metodología:**
- ✅ Usar **servidores locales de laboratorio** (ej: Docker con apps vulnerables)
- ✅ Usar **aplicaciones deliberadamente vulnerables** (ej: OWASP Juice Shop, WebGoat)
- ✅ **No ejecutar pruebas** contra sistemas públicos sin autorización expresa
- ✅ Comparar resultados con **herramientas reconocidas** (OWASP Benchmark, Bandit, Semgrep)

**Métricas de precisión:**
Si se declara un porcentaje de precisión, **explicar claramente:**
- Dataset utilizado
- Número de casos de prueba
- Verdaderos positivos (TP)
- Falsos positivos (FP)
- Falsos negativos (FN)
- Verdaderos negativos (TN)
- Método de evaluación

---

## 📚 DOCUMENTACIÓN Y TRANSPARENCIA

**Actualizar:**
- README.md
- Arquitectura (docs/ARCHITECTURE.md)
- Instalación (docs/INSTALLATION.md)
- Configuración (docs/CONFIGURATION.md)
- Manual de uso (docs/USAGE.md)
- Modelo de autorización (docs/AUTHORIZATION.md)
- Modelo de amenazas (docs/THREAT_MODEL.md)
- Limitaciones (docs/LIMITATIONS.md)
- Referencia de módulos (docs/MODULES.md)
- Ejemplos de informes (docs/EXAMPLES/)

**Diferenciar claramente entre:**
- ✅ **Implementado y probado**
- ⚠️ **Implementado parcialmente**
- 🧪 **Experimental**
- 📝 **Planificado**
- ❌ **No soportado**

**Regla clave:** **No presentar capacidades futuras como funcionalidades actuales.**

---

## 📅 METODOLOGÍA DE IMPLEMENTACIÓN

**Trabajar por fases.** No intentar modificar todo a la vez.

### **🔴 FASE 1: Seguridad del auditor** (Prioridad CRÍTICA)
**Objetivo:** Proteger el auditor y los sistemas auditados.

- [ ] Scope Manager (control centralizado de red)
- [ ] Validación de redirecciones
- [ ] Validación DNS segura
- [ ] Almacenamiento seguro de credenciales
- [ ] Engagement Manager (autorizaciones)
- [ ] Kill switch

**Criterio de aceptación:**
- ✅ Todas las conexiones de red pasan por Scope Manager
- ✅ Credenciales nunca en texto claro
- ✅ Cada operación activa valida engagement
- ✅ Tests de seguridad pasan

---

### **🟠 FASE 2: Fiabilidad** (Prioridad ALTA)
**Objetivo:** Reducir falsos positivos y mejorar precisión.

- [ ] Evidence Engine (motor de evidencias)
- [ ] Pruebas de control positivo/negativo
- [ ] Reducción de falsos positivos
- [ ] Máquina de estados (transiciones de vulnerabilidades)
- [ ] Tests de regresión

**Criterio de aceptación:**
- ✅ <10% falsos positivos en benchmarks
- ✅ Cada CONFIRMED tiene evidencia reproducible
- ✅ Tests de regresión pasan

---

### **🟡 FASE 3: Calidad del código** (Prioridad MEDIA)
**Objetivo:** Mejorar mantenibilidad y robustez.

- [ ] Auditar dependencias (requirements.txt)
- [ ] Eliminar dependencias innecesarias
- [ ] Fijar versiones
- [ ] Manejo de errores consistente
- [ ] Logging estructurado
- [ ] Tipado estricto
- [ ] Documentación completa

**Criterio de aceptación:**
- ✅ Todas las dependencias auditadas
- ✅ Tipado en >80% del código
- ✅ Documentación completa

---

### **🟢 FASE 4: Multilenguaje** (Prioridad MEDIA)
**Objetivo:** Extender soporte a más lenguajes.

- [ ] Arquitectura de analizadores
- [ ] Analizador JavaScript
- [ ] Analizador TypeScript
- [ ] Analizador Java (opcional)
- [ ] Analizador PHP (opcional)

**Criterio de aceptación:**
- ✅ Arquitectura extensible
- ✅ Al menos 2 lenguajes nuevos con pruebas

---

### **🔵 FASE 5: Inteligencia Artificial** (Prioridad BAJA)
**Objetivo:** Mejorar interpretación de resultados.

- [ ] Interpretación contextual
- [ ] Priorización automática
- [ ] Recomendaciones de corrección
- [ ] Correlación de hallazgos
- [ ] Supervisión humana (obligatoria)

**Criterio de aceptación:**
- ✅ IA ayuda pero **no decide**
- ✅ Supervisión humana obligatoria

---

## ✅ REGLAS DE ENTREGA

**Al finalizar cada fase:**
1. Explicar los **archivos modificados**
2. Explicar los **problemas corregidos**
3. Ejecutar los **tests**
4. Mostrar los **resultados reales**
5. Identificar los **tests pendientes**
6. Documentar **posibles regresiones**
7. **No ocultar fallos**
8. **No marcar una fase como completada** si no pasa sus criterios de aceptación

**Antes de finalizar el proyecto:**
- [ ] Resumen ejecutivo
- [ ] Arquitectura final
- [ ] Lista de vulnerabilidades del auditor corregidas
- [ ] Tests ejecutados y resultados
- [ ] Funcionalidades implementadas
- [ ] Funcionalidades pendientes
- [ ] Riesgos residuales
- [ ] Instrucciones para ejecutar v2.2

---

## 🎯 OBJETIVO FINAL

**Conseguir que Security Advisor Auditor sea:**
1. ✅ **Modular** (componentes desacoplados)
2. ✅ **Seguro** (no pone en riesgo sistemas auditados ni al auditor)
3. ✅ **Reproducible** (mismos inputs → mismos outputs)
4. ✅ **Profesional** (informes detallados y útiles)

**Prioridades (en orden):**
1. 🔴 **No poner en riesgo los sistemas auditados**
2. 🔴 **No poner en riesgo al propio auditor**
3. 🟠 **No generar falsos positivos innecesarios**
4. 🟠 **Proporcionar evidencias verificables**
5. 🟡 **Ofrecer recomendaciones técnicamente correctas**
6. 🟡 **Mantener una arquitectura extensible**

---

## 🚀 PRIMEROS PASOS

1. **Inspeccionar el repositorio** (YA HECHO → ver `INSPECCION_INICIAL.md`)
2. **Presentar diagnóstico y plan** (YA HECHO → ver `INSPECCION_VIBE_CODING.md`)
3. **Empezar por FASE 1: Seguridad del auditor**
   - Scope Manager
   - Almacenamiento seguro de credenciales
   - Engagement Manager

**¿Listo para empezar con la implementación?** 🛠️
