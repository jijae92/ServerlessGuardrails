"""Allow ``python -m scanner`` to behave like the CLI entry point."""

from .cli import main

if __name__ == "__main__":  # pragma: no cover
    main()
