"""Conftest de tests: hace importables los modulos auxiliares de tests/."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
