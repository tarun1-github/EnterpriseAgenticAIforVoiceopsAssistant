"""Pytest configuration and shared fixtures."""

import sys
from pathlib import Path

# Ensure root directory is on pythonpath for tests
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
