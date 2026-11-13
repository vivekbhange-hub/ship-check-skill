"""Load helper scripts by path (skill folders have hyphens, so they are not packages)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(skill: str, script: str):
    """Import skills/<skill>/<script>.py as a module named <script>_under_test."""
    return load_path(ROOT / "skills" / skill / f"{script}.py", f"{script}_under_test")


def load_path(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write(root: Path, rel: str, text: str) -> Path:
    """Write a text file (LF endings) under `root`, creating parent folders."""
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path
