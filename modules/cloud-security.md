# Cloud, CI/CD y despliegue — fases 18–20

Inventariar IaC/Docker/Kubernetes/workflows, IAM y límites de red. El motor solo
detecta superficie de infraestructura; no hace evaluación IAM ni consultas cloud.
Revisar root/privileged, mounts, secretos en imágenes/state, buckets, permisos CI,
pull_request_target, acciones sin pinning y provenance con evidencias locales.

La configuración declarativa no prueba el estado desplegado. Marcar pendientes
IAM efectivo, branch protections y TLS real hasta acceso autorizado. No conectarse
a cuentas por credenciales encontradas. Fuente: [NIST SSDF](https://csrc.nist.gov/Projects/ssdf).
