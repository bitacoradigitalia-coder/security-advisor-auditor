# 🔒 Branch Protection Configuration

Este archivo documenta la configuración recomendada de **Branch Protection** para el repositorio.

---

## 📋 Configuración para la rama `main`

### ⚙️ Settings > Branches > Branch protection rules

**Branch name pattern:** `main`

---

## ✅ Reglas de Protección Recomendadas

### 1. **Require status checks to pass before merging**

**Status checks that are required:**
- [x] `CI Tests` (GitHub Actions workflow)
- [x] `CodeQL` (opcional, para análisis de seguridad)

**Require branches to be up to date before merging:** ✅

---

### 2. **Require a pull request before merging**

- [x] Require approvals
- **Number of approvals required:** `1` (mínimo)
- **Dismiss stale pull request approvals when new commits are pushed:** ✅

---

### 3. **Require linear history**

- [ ] No requerido (pero recomendado para proyectos grandes)

---

### 4. **Require conversation resolution before merging**

- [x] ✅ Requerido

---

### 5. **Require signed commits**

- [ ] No requerido (pero recomendado para proyectos críticos)

---

### 6. **Require deployments to succeed**

- [ ] No aplicable (no hay deployments automáticos)

---

### 7. **Lock branch**

- [ ] No bloquear (permitir pushes directos a main)

---

### 8. **Require code owner reviews**

- [ ] No requerido (no hay CODEOWNERS configurado)

**Para habilitar:** Crear archivo `.github/CODEOWNERS`

---

### 9. **Restrict who can push to matching branches**

- [ ] No restringir (o restringir a mantenedores)

**Recomendación:** Restringir a usuarios con permiso `admin` o `maintain`

---

### 10. **Restrict who can dismiss approvals**

- [ ] No restringir (o restringir a mantenedores)

---

### 11. **Require branches to be up to date before merging**

- [x] ✅ Requerido

---

### 12. **Block force pushes**

- [x] ✅ Bloquear force pushes

---

### 13. **Block deletions**

- [x] ✅ Bloquear eliminaciones

---

## 📝 Configuración Recomendada (Resumen)

```yaml
# Configuración equivalente (para referencia)
branch_protection:
  main:
    required_status_checks:
      strict: true
      contexts: ["CI Tests"]
    
    required_pull_request_reviews:
      dismiss_stale_reviews: true
      required_approving_review_count: 1
    
    enforce_admins: false
    require_linear_history: false
    
    restrictions:
      users: []
      teams: []
    
    required_conversation_resolution: true
    required_signatures: false
    
    lock_branch: false
    allow_force_pushes: false
    allow_deletions: false
```

---

## 🚀 Pasos para Configurar

1. **Ve a** `Settings > Branches` en GitHub
2. **Haz clic en** `Add branch protection rule`
3. **Branch name pattern:** `main`
4. **Habilita todas las opciones recomendadas** arriba
5. **Guarda** la configuración

---

## 📁 Archivos Relacionados

- [.github/workflows/ci-tests.yml](workflows/ci-tests.yml) - Workflow de CI
- [.github/CONTRIBUTING.md](CONTRIBUTING.md) - Guía de contribución
- [.github/CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Código de conducta

---

## 🔒 Configuración Adicional Recomendada

### CODEOWNERS

Crea un archivo `.github/CODEOWNERS` para asignar responsables:

```
# .github/CODEOWNERS

# Mantenedores del proyecto
* @bitacoradigitalia-coder

# Documentación
/docs/ @bitacoradigitalia-coder

# Scripts
/scripts/ @bitacoradigitalia-coder

# Tests
tests/ @bitacoradigitalia-coder
```

### Secret Scanning

Habilita **Secret scanning** en:
- `Settings > Security > Secret scanning`
- GitHub escaneará automáticamente por tokens y credenciales

### Dependabot

Habilita **Dependabot** para actualizaciones automáticas:
- `Settings > Security > Dependabot`
- Configura para actualizar `requirements.txt` semanalmente

---

## 📊 Verificación

Para verificar que la protección está configurada correctamente:

1. **Intenta hacer push directo a main:**
   ```bash
   git push origin main
   # Debería fallar con error de protección
   ```

2. **Intenta hacer force push:**
   ```bash
   git push --force origin main
   # Debería fallar con error de protección
   ```

3. **Crea un PR sin approvals:**
   - El PR no debería poder ser mergeado

---

## 🎯 Recomendaciones para Contribuidores

1. **Siempre usa pull requests** para cambios en `main`
2. **Espera a que los tests pasen** antes de mergear
3. **Obtén al menos 1 aprobación** de un mantenedor
4. **Resuelve todas las conversaciones** antes de mergear
5. **No hagas force push** a ramas con protección

---

## 📚 Recursos

- [GitHub Docs: Branch Protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub Docs: CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [GitHub Docs: Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
