"""Source code helper utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Generator, Iterable


def iter_code_files(root_paths: Iterable[str], extensions: tuple[str, ...] = (".py",)) -> Generator[Path, None, None]:
    """Yield code files beneath the provided directories."""

    for root in root_paths:
        for path in Path(root).rglob("*"):
            if path.suffix in extensions and path.is_file():
                yield path
