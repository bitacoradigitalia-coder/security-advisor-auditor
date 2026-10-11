from pathlib import Path
base = Path("/uploads").resolve()
p = (base / input()).resolve()
if not p.is_relative_to(base):
    raise ValueError()
open(p)
