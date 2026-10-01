"""Test database isolation. Environment is set before the application imports."""

import os
import tempfile
from pathlib import Path

_ROOT = Path(tempfile.mkdtemp(prefix="cybertrace-tests-"))
os.environ["CYBERTRACE_DATA_DIR"] = str(_ROOT)
os.environ["CYBERTRACE_DATABASE_URL"] = "sqlite:///" + (_ROOT / "test.db").as_posix()
