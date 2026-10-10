# API — fases 3–5, 10–11, 15

Inventariar método/ruta, identidad, rol, objeto, propietario y tenant. Trazar
cada lectura, escritura y efecto; incluir campos sensibles, mass assignment,
GraphQL batching/depth, versiones antiguas, gRPC y consumidores de colas.
Revisar claves de máquinas, revocación, firmas webhook, replay y cuotas.

No inferir acceso público por nombre de ruta. Distinguir middleware global,
autorización de función y de objeto. Usar pares de usuarios/tenants sintéticos
en sandbox autorizado para regresión; no llamar servicios públicos de forma
automática. Fuente: [OWASP API Security](https://owasp.org/www-project-api-security/).
