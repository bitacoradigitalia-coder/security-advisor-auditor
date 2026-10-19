# Dependencias y supply chain — fases 17–18

Inventariar manifests/lockfiles y gestores. El helper lista archivos; NO consulta
advisories ni resuelve versiones transitivas. Revisar scripts de instalación,
fuentes, acciones CI, pinning y permisos. No ejecutar npm/pip ni scripts del
objetivo sin aislamiento. Un paquete antiguo no es por sí una vulnerabilidad.

Para advisory confirmado: fuente del fabricante/OSV, versión instalada,
rango afectado y uso/alcanzabilidad. Scanners opcionales se descubren, no se
ejecutan; salida redactada y condiciones de red deben aprobarse separadamente.
Fuente: [OSV-Scanner](https://google.github.io/osv-scanner/).
