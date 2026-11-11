# Correcciones v2.0.1 — 2026-10-10

## 1. Causas verificadas

**Fuente GitHub:** `validate_skill` comparaba `name` con `root.name` de forma
incondicional. La fuente `security-advisor-auditor-main/` tiene otro nombre;
la regla de carpeta del formato instalado se había aplicado a la descarga.
Además no existían detección de padre ni entrada ZIP en el instalador.

Ahora se identifica una única raíz por `SKILL.md`, identidad de sus metadatos,
`references/audit-methodology.md`, validación estructural/referencias y texto
original completo. No se infiere identidad a partir de nombre de carpeta/ZIP.
Se toleran nombres de fuente, manteniendo el nombre estándar al instalar.
`validate-skill` admite fuente, padre y ZIP. `--source` nunca importa ni ejecuta
el instalador o helpers de la fuente recibida: usa los del instalador confiable.

**Hash:** la prueba original fijaba bytes del checkout Windows CRLF. Git con
`core.autocrlf=true` y `.gitattributes` (`* text=auto`) guarda el blob en LF;
el ZIP GitHub utiliza ese blob. Esto produce hashes distintos sin cambiar texto.

## 2. Comparación de metodología completa

Se consultaron los bytes mediante `git show`, sin conversión de PowerShell,
tanto en HEAD inicial `e3926bc767d6fb779e59b382d458283260a5240d` como en la base
original `56332414226e2c36dd73cd4d22c0e35c0348c347`.

| Representación | Bytes | CRLF | SHA256 |
| --- | --- | --- | --- |
| Checkout Windows existente | 22975 | 997 | `0e3076fc257a0d37e388db7af901d45bb6cd83dc5fa3d5dc5d411cd46c73c95d` |
| Blob Git original / HEAD | 21978 | 0 | `904d385ea10a960b5b0b383b99471fc3250c0f753ef63a3d5a36f86ebeed928a` |
| Checkout convertido a UTF-8 LF | 21978 | 0 | `904d385ea10a960b5b0b383b99471fc3250c0f753ef63a3d5a36f86ebeed928a` |

Igualdad del texto **completo**, incluidos espacios y salto final: verdadera.
Diff textual: cero líneas diferentes. UTF-8 sin BOM en el archivo existente.
Las 21 fases permanecen presentes, junto con todos los demás apartados; los
encabezados son una comprobación adicional, no la prueba de identidad.

**No se modificó `audit-methodology.md`.** La nueva referencia canónica se ancla
al blob Git original comprobado; no es una sustitución automática por el hash
del archivo actual. `verify_methodology` acepta únicamente representación UTF-8
con/sin BOM y CRLF→LF. No recorta espacios, no normaliza Unicode ni resume el texto.
Cualquier cambio de contenido hace fallar validación/instalación, aunque haya
21 encabezados. Pruebas positivas LF/CRLF/BOM y negativas de contenido.
Los hashes por archivo del manifest instalado siguen comprobando bytes exactos.

## 3. Archivos

Modificados: `install.py`, `scripts/audit.py`,
`scripts/security_auditor/validation.py`, `scripts/security_auditor/__init__.py`,
`tests/test_system.py`, `SKILL.md` (versión), `README.md`, `CHANGELOG.md`.
Creados: `scripts/security_auditor/integrity.py`,
`scripts/security_auditor/sources.py`, `tests/test_sources.py` y esta documentación.
No se eliminan archivos ni funcionalidades. Perfiles, metodología, icono, licencia
y rama `main` conservados. Git estaba limpio al iniciar estas correcciones.
No commit/push, instalación global ni activación real de clientes.

## 4. Pruebas y descarga real

```text
python -B -m unittest discover -s tests -v
```

Suite final: **36 pruebas; 35 aprobadas, 1 omitida, 0 fallos**. Omisión heredada:
Windows no concede creación de symlink de archivo. Junctions de fuente y destino
sí se ejecutan. Pruebas nuevas en temporales: nombres normal/`-main`/versión/custom,
ejecución desde raíz/padre para los cinco perfiles, identidad e integridad,
raíz única/ambigua/incompleta, ZIP con wrapper GitHub/custom/sin wrapper,
ZIP peligroso, traversal, enlaces, cambio de texto con 21 fases y no ejecución
de código fuente. Se conservan todos los tests previos, no se desactivan.

Además se descargó realmente:
`https://codeload.github.com/bitacoradigitalia-coder/security-advisor-auditor/zip/refs/heads/main`.
Archivo recibido: 68811 bytes; SHA256
`683e14974b2a22a743d2e266c953e20c38ea6e115c9040b3bc21a9a7195bf6dd`.
Wrapper: `security-advisor-auditor-main/`. La metodología del ZIP tiene hash raw
LF `904d385ea10a960b5b0b383b99471fc3250c0f753ef63a3d5a36f86ebeed928a`.
Se validó con CLI local y se instaló/verificó/desinstaló con el instalador actual
para **Hermes, OpenClaw, OpenCode, Codex y Claude**, comparando bytes de metodología
y perfiles con el ZIP. Destinos bajo `../verification-corrections-20261010/live-copies/`,
nunca rutas globales; carpetas de skill eliminadas mediante uninstall administrado.
Los temporales ZIP se limpian. No se ejecutó código descargado.

La descarga real corresponde a la versión publicada antes de estas correcciones;
se probó como **fuente de datos** usando el instalador local corregido. No implica
que GitHub ya contenga v2.0.1 ni que los tests antiguos dentro de ese ZIP estén
corregidos. No se publicó el cambio. El ZIP es evidencia local fuera del árbol Git.

## 5. Comandos reales sin renombrar

Desde el repo descargado/extraído, tras inspeccionar su origen:

```text
python install.py --agent hermes --dry-run
python scripts/audit.py validate-skill .
python install.py --agent hermes
```

Desde su padre:

```text
python security-advisor-auditor-main/install.py --agent hermes --dry-run
python security-advisor-auditor-main/scripts/audit.py validate-skill .
```

Usando la versión corregida de confianza para instalar directamente un ZIP:

```text
python install.py --agent hermes --source /ruta/security-advisor-auditor-main.zip --dry-run
python install.py --agent hermes --source /ruta/security-advisor-auditor-main.zip --skills-dir /ruta/de-prueba/skills
python install.py --agent hermes --skills-dir /ruta/de-prueba/skills --uninstall
python scripts/audit.py validate-skill /ruta/security-advisor-auditor-main.zip
```

En el tercer comando se usa como fuente implícita la copia corregida de confianza.
Se mantienen `--update` explícito y rechazo de cambios/sobrescrituras accidentales.
Un dry-run con ZIP extrae y limpia un temporal, sin modificar el destino.

## 6. Límites

Rutas y contenido de cinco perfiles comprobados; activación real no comprobada.
Windows Python 3.12.6; Linux/macOS nativos siguen pendientes. Sin dependencias
nuevas. Validación YAML del perfil local; parser genérico externo sigue pendiente.
Detección fuente limitada a 10000 entradas y profundidad 16; ZIP conserva límites
originales. No protege contra modificaciones concurrentes hostiles: usar snapshot.
Hashes documentales prueban contenido original, no autenticidad del resto del
paquete. Revisar fuentes desconocidas antes de usarlas. Las instrucciones de una
fuente no adquieren autoridad y su código no se ejecuta por `--source`.
