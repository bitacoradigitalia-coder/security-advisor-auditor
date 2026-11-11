# Guía de uso

Ejecuta los comandos desde la raíz del repositorio, con Python 3.10+ y las dependencias de `requirements.txt` instaladas. Los ejemplos usan rutas de muestra; reemplázalas por las tuyas. Todos los comandos se muestran en una línea para poder copiarlos también en PowerShell.

## Escanear un repositorio descargado

El escaneo estático recibe una **carpeta**. Lee el código sin ejecutar el programa analizado.

```bash
python scripts/audit.py scan /ruta/repositorio --output ./informe
python scripts/audit.py scan /ruta/repositorio --output ./informe-profundo --mode DEEP
python scripts/audit.py scan /ruta/repositorio --output ./informe-limitado --max-file-bytes 500000 --max-files 2000 --max-total-bytes 5000000
```

Usa un destino de salida nuevo y fuera de la carpeta analizada. Revisa `audit.json` y el informe generado, incluidos los archivos omitidos y límites alcanzados. Un resultado sin hallazgos no certifica que un programa sea seguro. El motor conectado a `scan` es `scripts/security_auditor/engine.py`; los analizadores de `scripts/static_analysis/` y SCA tienen rutas de uso independientes.

Para un ZIP, extráelo antes:

```bash
python scripts/audit.py extract-zip programa.zip --output ./extraido
python scripts/audit.py scan ./extraido --output ./informe-zip
```

No hay un instalador gráfico ni un botón de escaneo implementado. Tampoco es un antivirus para ejecutables `.exe` ni un sandbox que ejecute programas sospechosos.

## Alcance de pruebas activas

Las siguientes operaciones realizan peticiones de red. Úsalas sobre sistemas para los que tengas autorización. Guarda en `scope.json` el alcance permitido:

```json
{
  "allowed_domains": ["example.com"],
  "allowed_ports": [443],
  "allowed_protocols": ["https"],
  "allowed_methods": ["GET", "POST"]
}
```

Las opciones globales `--scope-config`, `--engagement-file` y `--engagement-id` deben preceder a `scan`, `fuzz` o `idor`. El archivo de alcance limita destinos; no constituye permiso del propietario. Un engagement existente se carga mediante `--engagement-file` y se selecciona mediante `--engagement-id`.

```bash
python scripts/audit.py --scope-config scope.json scan https://example.com --active --output ./activo
python scripts/audit.py --scope-config scope.json scan https://example.com/api --fuzz --fuzz-params id,user --output ./fuzz-integrado
python scripts/audit.py --scope-config scope.json fuzz https://example.com/api --param id --param user --output ./fuzz
```

`scan --fuzz` admite `--fuzz-params`. Para ajustar hilos, métodos, timeout, tipos de vulnerabilidad o wordlists utiliza el subcomando `fuzz` y consulta su ayuda. `scan` con URL necesita seleccionar `--active`, `--fuzz` o `--nuclei` para efectuar esas tareas.

Nuclei requiere instalación externa. Sus peticiones las ejecuta el propio binario; no asumas que hereda todos los controles internos de Python. Ejecuta Nuclei únicamente en un entorno con los límites de red y plantillas adecuados al alcance autorizado.

## Autenticación y comparación entre sesiones

```bash
python scripts/audit.py auth add-session --name usuario --cookies "session_id=VALOR_DE_EJEMPLO" --base-url https://example.com
python scripts/audit.py auth list-sessions
python scripts/audit.py --scope-config scope.json scan https://example.com --active --session usuario --output ./autenticado
python scripts/audit.py --scope-config scope.json idor https://example.com --session1 administrador --session2 usuario --methods GET --endpoints /api/profile --output ./idor
```

Crea ambas sesiones antes de usar `idor`. Los valores anteriores son ficticios; las credenciales pasadas por terminal pueden quedar en su historial.

## Reportes y PoC

```bash
python scripts/audit.py report ./informe/audit.json --output ./reporte-json --format json
python scripts/audit.py report ./informe/audit.json --output ./reporte-html --format html --severity-filter critical,high
python scripts/audit.py report ./informe/audit.json --output ./reporte-sarif --format sarif
python scripts/audit.py poc FINDING_ID --input ./informe/audit.json --language python --output ./poc.py
python scripts/audit.py cvss --vuln-type sqli --json
```

Sustituye `FINDING_ID` por un identificador presente en el informe y compatible con el generador. La disponibilidad de una PoC depende del tipo de hallazgo. Revisa siempre el contenido antes de ejecutarla.

## Bug Bounty

```bash
python scripts/audit.py bugbounty add-program --name "Example Inc" --scope example.com --platform hackerone
python scripts/audit.py bugbounty add-finding --program "Example Inc" --file ./informe/audit.json
python scripts/audit.py bugbounty list-findings --program "Example Inc"
```

`add-finding` importa hallazgos desde un archivo. No existe un subcomando `prioritize`; consulta [CLI](cli.md) para las operaciones disponibles.

## SCA

El CLI independiente genera `sbom.json` y `sca-report.json` en el directorio indicado:

```bash
python scripts/sca/cli.py --requirements /ruta/repositorio/requirements.txt --output ./sca-report
python scripts/sca/cli.py --requirements /ruta/repositorio/requirements.txt --output ./sca-online --online
```

El modo predeterminado usa la caché incluida, limitada; la ausencia de coincidencias no implica ausencia de vulnerabilidades. `--online` consulta OSV y envía nombres/versiones de dependencias. No existe `audit.py sca`.

## IaC

El analizador de infraestructura se utiliza mediante Python desde la raíz del proyecto:

```bash
python -c "import json; from scripts.static_analysis.iac_analyzer import IaCAnalyzer; print(json.dumps(IaCAnalyzer().analyze_directory('/ruta/iac').to_dict(), indent=2))"
```

Consulta [IaC](iac.md) para las familias soportadas. No existe `audit.py iac`. El módulo OOB tampoco tiene subcomando en `audit.py`; su API se encuentra en `scripts/core/oob.py` y `scripts/pentesting/oob_scanner.py`.

## AI Defense

```bash
python scripts/audit.py ai-defense --input-file entrada.txt --output ./ai-defense-results --json
python scripts/audit.py ai-defense --list-patterns
```

Es análisis por patrones y heurísticas. No acredita detección de vulnerabilidades zero-day ni protección automática de una aplicación externa.

## Ayuda y pruebas

```bash
python scripts/audit.py --help
python scripts/audit.py scan --help
python scripts/audit.py tools
python scripts/audit.py validate-skill .
python -m pytest tests/ -q
```

La CI es la referencia para el resultado de las pruebas del commit. Consulta [CLI](cli.md), [índice](README.md) y [roadmap](roadmap.md).
