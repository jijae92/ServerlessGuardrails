"""Infrastructure-as-code helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from .fileio import read_yaml_file


def load_template(path: Path) -> Dict[str, Any] | None:
    """Load a SAM/CloudFormation template into a dictionary."""

    data = read_yaml_file(path)
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError(f"Template at {path} is not a mapping")
    return data
