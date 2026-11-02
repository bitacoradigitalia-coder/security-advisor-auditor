# 🔍 INSPECCIÓN INICIAL - Security Advisor Auditor v2.2
**Fecha:** 2026-11-02  
**Versión Base:** v2.1.1  
**Objetivo:** Evolucionar a v2.2 según especificaciones  
**Estado:** Análisis completado

---

## 📊 ESTADO ACTUAL

### 📁 Estructura (123 archivos)
```
scripts/
├── audit.py              # CLI principal (41KB, fixes aplicados)
├── security_auditor/     # Motor estático v2.1 (funcional)
│   ├── engine.py         # Triaje estático
│   ├── contextual.py     # Análisis contexto Python
│   ├── authorization.py  # Detección Flask/Flask-Login
│   ├── verification.py   # Máquina de estados
│   └── safeio.py         # Lectura segura
├── pentesting/           # Módulos v3.0 (funcionales pero sin Scope Manager)
│   ├── scanner.py        # Escaneo activo
│   ├── fuzzer.py         # Fuzzing
│   ├── exploit.py        # Explotación controlada
│   └── auth.py           # Autenticación (ALMACENAMIENTO INSEGURO)
├── bugbounty/            # Gestión de programas
└── reporting/           # Reportes
```

**Tests:** 156/156 ✅ pasando

---

## 🚨 PROBLEMAS CRÍTICOS v2.2

### 🔴 PRIORIDAD CRÍTICA: SEGURIDAD DEL AUDITOR

#### 1. **Falta Scope Manager Centralizado**
**Problema:** Cada módulo (scanner, fuzzer, exploit) hace conexiones de red **sin control centralizado**.

**Riesgos:**
- Accesos accidentales a localhost, redes privadas, metadatos cloud
- Redirecciones automáticas a destinos no autorizados
- Sin límites de peticiones/concurrencia
- Sin kill switch

**Solución:** Crear `scripts/core/scope_manager.py` con:
- Validación de dominios/IPs/puertos/protocolos
- Bloqueo de localhost, redes privadas (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254)
- Validación de redirecciones
- Límites de peticiones (rate limiting)
- Kill switch

**Acciones:**
- [ ] Crear módulo `scripts/core/scope_manager.py`
- [ ] Integrar en scanner.py, fuzzer.py, exploit.py
- [ ] Añadir validación DNS segura
- [ ] Tests de validación de scope

---

#### 2. **Almacenamiento Inseguro de Credenciales**
**Problema:** `scripts/pentesting/auth.py` almacena credenciales en **JSON sin cifrar**.

**Código problemático:**
```python
# auth.py
self.storage_path = storage_path
if self.storage_path and os.path.exists(self.storage_path):
    self._load_sessions()
# Lee JSON SIN cifrar
with open(self.storage_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
```

**Riesgos:**
- Credenciales en texto claro en disco
- No usa keyring del sistema
- Sin cifrado
- Permisos no restrictivos

**Solución:**
```python
# Usar keyring o cifrado
import keyring
from cryptography.fernet import Fernet

class SecureAuthManager:
    def store_credential(self, name, credential):
        if keyring.available:
            keyring.set_password("security_advisor", name, credential)
        else:
            encrypted = self.cipher.encrypt(credential.encode())
            # Guardar con permisos 600
```

**Acciones:**
- [ ] Implementar almacenamiento con keyring
- [ ] Cifrado para fallback
- [ ] Permisos 600 en archivos
- [ ] Redacción automática en logs
- [ ] Caducidad de sesiones
- [ ] Eliminación segura

---

#### 3. **Autorización de Operaciones de Pentesting**
**Problema:** `scripts/pentesting/exploit.py` tiene `PermissionManager` pero:
- No valida antes de CADA operación
- Comparación de wildcards insegura
- No hay modelo de engagement completo

**Riesgos:**
- Operaciones sin autorización válida
- Wildcards mal interpretados
- Autorizaciones caducadas no bloqueadas

**Solución:**
```python
@dataclass
class Engagement:
    id: str
    owner: str
    targets: List[str]  # Dominios/IPs EXACTOS
    start_time: datetime
    end_time: datetime
    allowed_types: List[str]
    rate_limits: Dict[str, int]

class EngagementManager:
    def validate(self, engagement_id, target, vuln_type):
        engagement = self.get(engagement_id)
        if not engagement:
            raise AuthorizationError("Engagement no encontrado")
        if datetime.now() > engagement.end_time:
            raise AuthorizationError("Engagement caducado")
        if target not in engagement.targets:
            raise AuthorizationError(f"Target {target} no autorizado")
        # Validar wildcard de forma segura
        if not self._safe_match(target, engagement.targets):
            raise AuthorizationError(f"Target no coincide")
```

**Acciones:**
- [ ] Crear modelo Engagement
- [ ] Validar antes de CADA operación activa
- [ ] Fix comparación wildcards (usar fnmatch o regex seguro)
- [ ] Bloquear operaciones sin engagement válido

---

### 🟠 PRIORIDAD ALTA: PRECISIÓN

#### 4. **Falsos Positivos en Fuzzer**
**Problema:** `scripts/pentesting/fuzzer.py` detecta vulnerabilidades basándose en:
- Status code 500
- Cadenas reflejadas
- Respuestas diferentes

**Riesgos:** Muchos falsos positivos, confianza mal asignada.

**Solución:** Implementar `EvidenceEngine` con:
- Pruebas de control positivo/negativo
- Comparación estructurada de respuestas
- Evidencia reproducible
- Confianza justificada (low/medium/high/confirmed)

**Acciones:**
- [ ] Implementar EvidenceEngine
- [ ] Añadir pruebas de control
- [ ] Reducir falsos positivos
- [ ] Distinguir detección vs confirmación

---

#### 5. **Estados de Vulnerabilidad**
**Problema:** No hay reglas claras para transiciones entre estados.

**Solución:** Definir máquina de estados con reglas verificables:
```python
TRANSITIONS = {
    'CANDIDATE': {
        'to_PROBABLE': ['context_verified', 'flow_analyzed'],
        'to_FALSE_POSITIVE': ['mitigation_verified']
    },
    'PROBABLE': {
        'to_CONFIRMED': ['evidence_reproducible', 'control_violation'],
        'to_CANDIDATE': ['new_evidence'],
        'to_FALSE_POSITIVE': ['mitigation_verified']
    }
}
```

**Regla crítica:** IA solo sugiere, **nunca confirma** sin evidencia.

---

### 🟠 PRIORIDAD ALTA: DEPENDENCIAS

#### 6. **Dependencias Problema en requirements.txt**
```txt
session>=0.0.0    # ❌ Versión sin límite, paquete genérico
cookies>=0.0.0    # ❌ No se usa en el código
```

**Riesgos:** Dependencias innecesarias, versiones inseguras.

**Solución:**
- Eliminar dependencias no usadas
- Fijar versiones: `requests==2.31.0`
- Añadir hashes: `--hash=sha256:...`
- Generar `requirements.lock`
- Escanear con `safety check` y `bandit`

---

## 📋 PLAN DE IMPLEMENTACIÓN

### 🎯 FASE 1: SEGURIDAD DEL AUDITOR (1-2 semanas)
**Objetivo:** Proteger el auditor de abusos y errores

| Tarea | Prioridad | Esfuerzo |
|-------|-----------|----------|
| Crear ScopeManager | 🔴 Crítica | 3 días |
| Integrar en scanner/fuzzer/exploit | 🔴 Crítica | 2 días |
| Almacenamiento seguro credenciales | 🔴 Crítica | 2 días |
| Engagement Manager | 🔴 Crítica | 2 días |
| Validación DNS segura | 🔴 Crítica | 1 día |
| Kill switch | 🔴 Crítica | 1 día |
| Límites de peticiones | 🔴 Crítica | 1 día |

**Criterio de aceptación:**
- ✅ Todas las conexiones de red pasan por ScopeManager
- ✅ Credenciales nunca en texto claro
- ✅ Cada operación activa valida engagement
- ✅ Tests de seguridad pasan

---

### 🎯 FASE 2: FIABILIDAD (1-2 semanas)
**Objetivo:** Reducir falsos positivos

| Tarea | Prioridad | Esfuerzo |
|-------|-----------|----------|
| EvidenceEngine | 🟠 Alta | 3 días |
| Pruebas de control | 🟠 Alta | 2 días |
| Reducir falsos positivos | 🟠 Alta | 3 días |
| Máquina de estados | 🟠 Alta | 2 días |

**Criterio:** <10% falsos positivos en benchmarks

---

### 🎯 FASE 3: CALIDAD (1 semana)
| Tarea | Prioridad | Esfuerzo |
|-------|-----------|----------|
| Auditar dependencias | 🟡 Media | 2 días |
| Eliminar innecesarias | 🟡 Media | 1 día |
| Tipado estricto | 🟡 Media | 3 días |

---

### 🎯 FASE 4: MULTILENGUAJE (2-3 semanas)
| Tarea | Prioridad | Esfuerzo |
|-------|-----------|----------|
| Arquitectura analizadores | 🟡 Media | 2 días |
| Analizador JavaScript | 🟡 Media | 3 días |
| Analizador TypeScript | 🟡 Media | 2 días |

---

### 🎯 FASE 5: IA (2 semanas)
| Tarea | Prioridad | Esfuerzo |
|-------|-----------|----------|
| Interpretación contextual | 🟢 Baja | 3 días |
| Priorización automática | 🟢 Baja | 2 días |

---

## 📊 ARQUITECTURA OBJETIVO v2.2

```
scripts/
├── main.py                    # Punto de entrada
├── core/                      # ✅ NUEVO: Componentes centralizados
│   ├── scope_manager.py      # Control de alcance
│   ├── engagement_manager.py  # Gestión de autorizaciones
│   ├── evidence_engine.py     # Motor de evidencias
│   ├── verification_engine.py # Validación de hallazgos
│   └── ai_engine.py           # IA (opcional)
├── security_auditor/         # Motor estático (existente)
├── pentesting/               # Módulos activos (integrar ScopeManager)
├── bugbounty/                # Gestión (existente)
└── reporting/                # Reportes (existente)
```

---

## ✅ RESUMEN

### **Lo que YA funciona:**
- Motor de análisis estático (Python AST)
- Arquitectura modular
- Tests completos (156/156)
- CLI funcional

### **Lo que FALTA para v2.2:**
1. **Scope Manager** (control de red)
2. **Almacenamiento seguro de credenciales**
3. **Engagement Manager** (autorización)
4. **Evidence Engine** (precisión)
5. **Dependencias limpias**
6. **Tipado estricto**

### **Prioridad:**
```
SEGURIDAD (FASE 1) > PRECISIÓN (FASE 2) > CALIDAD (FASE 3) > MULTILENGUAJE (FASE 4) > IA (FASE 5)
```

---

## 🎯 PRÓXIMO PASO

**¿Empezamos con FASE 1: Scope Manager?**

Si apruebas este diagnóstico, puedo empezar a implementar:
1. `scripts/core/scope_manager.py`
2. Integración en los módulos existentes
3. Tests de validación

**Responde "sí" para empezar.** 🚀
