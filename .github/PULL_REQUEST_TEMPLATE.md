---
name: Pull Request Template
about: Plantilla para Pull Requests
---

## 📝 Pull Request

**¡Gracias por tu contribución!**

---

### 🎯 Descripción

Una descripción clara y concisa de los cambios realizados.

**Issue relacionada:** [#123](https://github.com/bitacoradigitalia-coder/security-advisor-auditor/issues/123)

---

### 📋 Tipo de Cambio

- [ ] ✅ **Bug Fix** - Corrección de un error
- [ ] ✨ **New Feature** - Nueva funcionalidad
- [ ] 📚 **Documentation** - Mejoras en documentación
- [ ] 🎨 **UI/UX** - Mejoras en interfaz o experiencia de usuario
- [ ] 🔧 **Refactor** - Refactorización de código
- [ ] ⚡ **Performance** - Mejoras de rendimiento
- [ ] 🧪 **Tests** - Añadir o mejorar tests
- [ ] 📦 **Dependencies** - Actualización de dependencias
- [ ] 🔒 **Security** - Mejoras de seguridad
- [ ] 📝 **Chore** - Tareas de mantenimiento

---

### 🔧 Cambios Realizados

| Cambio | Descripción |
|--------|-------------|
| Archivo 1 | Descripción de lo cambiado |
| Archivo 2 | Descripción de lo cambiado |

**Archivos modificados:**
- `scripts/audit.py`
- `docs/cli.md`
- `tests/test_*.py`

**Archivos nuevos:**
- `scripts/nuevo_modulo.py`
- `docs/nueva_guia.md`

**Archivos eliminados:**
- `scripts/obsoleto.py`

---

### ✅ Checklist

**Código:**
- [ ] El código sigue el estilo del proyecto (PEP 8)
- [ ] He añadido type hints donde es apropiado
- [ ] He añadido docstrings para funciones/métodos públicos
- [ ] El código es compatible con Python 3.10+

**Tests:**
- [ ] Todos los tests existentes pasan
- [ ] He añadido tests para el nuevo código
- [ ] Los tests cubren casos normales y edge cases

**Documentación:**
- [ ] He actualizado la documentación si es necesario
- [ ] He actualizado el README si es necesario
- [ ] He actualizado el CHANGELOG si es necesario

**Seguridad:**
- [ ] No he añadido credenciales o secretos
- [ ] He sanitizado todas las entradas de usuario
- [ ] He seguido las buenas prácticas de seguridad

---

### 🧪 Testing

**Comandos ejecutados:**
```bash
# Ejemplo:
python -B -m unittest discover -s tests -v
mypy scripts/
python scripts/audit.py --help
```

**Resultados:**
- [ ] Todos los tests pasan
- [ ] Type checking pasa (mypy)
- [ ] El CLI funciona correctamente

---

### 📸 Capturas de Pantalla (Opcional)

Si el PR incluye cambios visuales, añade capturas de pantalla aquí.

---

### 🔍 Notas Adicionales

- **Breaking Changes:** [Sí/No] - Si sí, describe cómo afecta a los usuarios
- **Dependencias nuevas:** [Sí/No] - Si sí, lista las nuevas dependencias
- **Configuración requerida:** [Sí/No] - Si sí, describe la configuración necesaria

---

### ✨ Reviewers

@bitacoradigitalia-coder

---

**¡Gracias por tu contribución!** 🙌
