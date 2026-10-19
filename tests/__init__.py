"""
Test suite for Security Advisor Auditor v3.0
"""
import sys
from pathlib import Path

# Add scripts directory to path for imports
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
