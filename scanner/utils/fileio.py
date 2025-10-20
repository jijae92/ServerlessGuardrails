"""Basic file IO helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class CloudFormationLoader(yaml.SafeLoader):
    """YAML loader that tolerates CloudFormation/SAM intrinsic tags."""


def _construct_intrinsic(loader: CloudFormationLoader, tag_suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def read_yaml_file(path: Path) -> Any:
    """Return the parsed YAML if the file exists, otherwise ``None``."""

    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return yaml.load(handle, Loader=CloudFormationLoader)


def read_text_file(path: Path) -> str:
    """Return the file contents as UTF-8 text, or an empty string if missing."""

    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")
