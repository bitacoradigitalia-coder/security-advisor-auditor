from pathlib import Path
base = Path("/uploads").resolve()
p = (base / input()).resolve()
if not str(p).startswith(str(base)):
    raise ValueError()
open(p)
