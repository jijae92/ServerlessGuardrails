"""Serverless Guardrails static scanner package."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("serverless-guardrails")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.1.0-dev"

__all__ = ["__version__"]
