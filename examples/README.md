# 📁 Examples - Ejemplos de Uso

Este directorio contiene **ejemplos sintéticos** para demostrar las capacidades de **Security Advisor Auditor**.

---

## 🗂️ Estructura

```
examples/
├── README.md                    # 📍 Este archivo
├── evidence_example.py          # Ejemplo de generacin de evidencias
├── safe/                       # Ejemplos de cdigo SEGURO
│   ├── app.py                  # Aplicacin Flask segura
│   └── client.js               # Cliente JavaScript seguro
└── vulnerable/                  # Ejemplos de cdigo VULNERABLE
    ├── app.py                  # Aplicacin Flask con vulnerabilidades
    └── client.js               # Cliente JavaScript con vulnerabilidades
```

---

## ⚠️ ADVERTENCIA IMPORTANTE

> **⚠️ ESTOS SON EJEMPLOS SINTÉTICOS PARA PRUEBAS**
> 
> - **NO son módulos para importar** en tu código
> - **NO son pruebas para ejecutar** directamente
> - **NO contienen credenciales reales**
> - **Son inputs estáticos** para el motor de análisis
> - **Nunca ejecutar** el código vulnerable en producción

---

## 🎯 Ejemplos de Uso

### Análisis de Ejemplos Vulnerables

```bash
# Escanear el directorio vulnerable
python scripts/audit.py scan examples/vulnerable --output ./example-vulnerable-report

# Resultados esperados:
# - 5+ candidatos detectados
# - CWE-78 (OS Command Injection)
# - CWE-95 (Improper Neutralization of Directives)
# - CWE-502 (Deserialization of Untrusted Data)
# - CWE-295 (Improper Certificate Validation)
# - CWE-79 (Cross-site Scripting)
```

### Análisis de Ejemplos Seguros

```bash
# Escanear el directorio seguro
python scripts/audit.py scan examples/safe --output ./example-safe-report

# Resultados esperados:
# - 0 candidatos (o falsos positivos mnimos)
# - Sin vulnerabilidades confirmadas
# - Uso seguro de funciones y librers
```

### Comparacin entre Ejemplos

```bash
# Analizar ambos y comparar resultados
python scripts/audit.py scan examples/vulnerable --output ./compare-vulnerable
python scripts/audit.py scan examples/safe --output ./compare-safe

# Generar reportes para comparacin
python scripts/audit.py report ./compare-vulnerable/audit.json --output ./report-vulnerable --format html
python scripts/audit.py report ./compare-safe/audit.json --output ./report-safe --format html
```

---

## 📚 Descripcin de Ejemplos

### 🔴 vulnerable/app.py

Aplicacin Flask **deliberadamente insegura** con las siguientes vulnerabilidades:

| Vulnerabilidad | Tipo | CWE | Descripcin |
|----------------|------|-----|-------------|
| Command Injection | OS Command Injection | CWE-78 | Uso de `os.system()` con entrada de usuario |
| Template Injection | Improper Neutralization | CWE-95 | Renderizado de plantillas con entrada de usuario |
| Deserialization | Deserialization of Untrusted Data | CWE-502 | Deserializacin de datos no confiables |
| SSL Verification | Improper Certificate Validation | CWE-295 | Deshabilitacin de verificacin SSL |
| XSS | Cross-site Scripting | CWE-79 | Renderizado de HTML con entrada de usuario |

**Propsito**: Demostrar la capacidad de deteccin de vulnerabilidades del motor de anlisis esttico.

**⚠️ NO EJECUTAR EN PRODUCCIN**

---

### 🟢 safe/app.py

Aplicacin Flask **segura** que demuestra:

| Buena Prctica | Descripcin |
|---------------------|-------------|
| Uso de consultas parametrizadas | Evita SQL Injection |
| Sanitizacin de entrada | Evita XSS y Command Injection |
| Validacin de certificados SSL | Conexiones seguras |
| Uso de librers seguras | `subprocess` en lugar de `os.system` |
| Serializacin segura | Uso de formatos seguros |

**Propsito**: Demostrar que el motor NO genera falsos positivos con cdigo seguro.

---

### 🔴 vulnerable/client.js

Cliente JavaScript con vulnerabilidades comunes:

| Vulnerabilidad | Tipo | Descripcin |
|----------------|------|-------------|
| DOM XSS | Cross-site Scripting | CWE-79 | Manipulacin del DOM con entrada de usuario |
| Insecure Storage | Client-side Storage | - | Almacenamiento de tokens en localStorage |
| Missing Input Validation | Input Validation | - | Falta validacin de entrada |

---

### 🟢 safe/client.js

Cliente JavaScript seguro con:

| Buena Prctica | Descripcin |
|---------------------|-------------|
| Encoding de salida | Evita XSS |
| Validacin de entrada | Previene inyecciones |
| Almacenamiento seguro | Uso de cookies con HttpOnly y Secure |
| Sanitizacin | Limpieza de datos de usuario |

---

### 📋 evidence_example.py

Ejemplo de **generacin de evidencias** para hallazgos.

**Propsito**: Demostrar cmo el motor genera evidencias trazables para cada hallazgo.

**Contenido**:
- Ejemplo de estructura de evidencia
- Relacin entre hallazgo, ubicacin y contexto
- Formato de salida estndar

---

## 🎯 Casos de Prueba

### Prueba de Regresin

```bash
# Ejecutar prueba de regresin bsica
python -B -m unittest tests.test_contract -v

# Verificar que vulnerable/ genera hallazgos
python -B -m unittest tests.test_precision -v
```

### Prueba de Precisin

```bash
# Verificar precisin del motor
python -B tests/evaluate_precision.py --output ./precision-evaluation

# Esperado: 100% de precisin en el corpus de ejemplos
```

---

## 📊 Resultados Esperados

### Para vulnerable/

```json
{
  "findings": [
    {
      "id": "...",
      "severity": "high",
      "type": "vulnerability",
      "cwe": "CWE-78",
      "location": {
        "file": "examples/vulnerable/app.py",
        "line": 15,
        "function": "execute_command"
      },
      "description": "OS Command Injection",
      "status": "CANDIDATE"
    },
    {
      "id": "...",
      "severity": "high",
      "type": "vulnerability",
      "cwe": "CWE-95",
      "location": {
        "file": "examples/vulnerable/app.py",
        "line": 25,
        "function": "render_template"
      },
      "description": "Template Injection",
      "status": "CANDIDATE"
    }
  ],
  "summary": {
    "total_findings": 5,
    "vulnerabilities": 5,
    "weaknesses": 0,
    "critical": 2,
    "high": 3
  }
}
```

### Para safe/

```json
{
  "findings": [],
  "summary": {
    "total_findings": 0,
    "vulnerabilities": 0,
    "weaknesses": 0,
    "critical": 0,
    "high": 0
  }
}
```

---

## 🔧 Personalizacin

### Aadir Nuevos Ejemplos

Para aadir nuevos ejemplos:

1. **Crea un nuevo directorio** en `examples/`
2. **Aade archivos** con cdigo de ejemplo
3. **Documenta** el propsito y vulnerabilidades esperadas
4. **Actualiza este README** con la descripcin

**Ejemplo**:
```bash
mkdir examples/new-feature
cp examples/vulnerable/app.py examples/new-feature/app.py
# Modificar app.py para demostrar nueva funcionalidad
```

### Modificar Ejemplos Existentes

**⚠️ ADVERTENCIA**: Los ejemplos actuales estn **congelados** como baseline para pruebas de regresin.

Si modificas los ejemplos:
1. **Actualiza las pruebas** de regresin
2. **Documenta los cambios** en el CHANGELOG
3. **Verifica que los tests pasan**

---

## 🧪 Tests Relacionados

Los ejemplos se usan en los siguientes tests:

| Test | Propsito | Archivo |
|------|---------|--------|
| test_contract | Validacin de contrato de skill | `tests/test_contract.py` |
| test_precision | Precisin del motor de anlisis | `tests/test_precision.py` |
| evaluate_precision | Evaluacin de precisin | `tests/evaluate_precision.py` |

---

## 📚 Recursos Adicionales

- [Documentacin de CLI](../docs/cli.md) - Referencia completa de comandos
- [Gu de Uso](../docs/usage.md) - Ejemplos prcticos
- [Metodolog de Auditor](../references/audit-methodology.md) - 21 fases completas

---

**Nota**: Estos ejemplos son **sintticos** y estn diseados especficamente para pruebas. No representan un entorno de produccin real.
