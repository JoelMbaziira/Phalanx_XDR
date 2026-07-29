"""pytest configuration — adds the sentinel agent to sys.path."""
import sys
from pathlib import Path

# Make sentinel.py importable without installing it
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agents" / "sentinel-py"))
