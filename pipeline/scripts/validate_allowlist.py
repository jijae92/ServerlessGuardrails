"""Validate .guardrails-allow.json entries for expiry metadata."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ALLOW_FILE = Path(".guardrails-allow.json")
TODAY = datetime.utcnow().date()
EXP_PREFIX = "__EXP_"


def main() -> int:
    if not ALLOW_FILE.exists():
        return 0

    data = json.loads(ALLOW_FILE.read_text(encoding="utf-8"))
    env_names = data.get("env_names", [])
    errors: list[str] = []
    for name in env_names:
        upper = str(name).upper()
        if EXP_PREFIX not in upper:
            errors.append(f"{name}: missing {EXP_PREFIX}YYYY-MM-DD suffix")
            continue
        suffix = upper.split(EXP_PREFIX, 1)[1]
        try:
            expiry = datetime.strptime(suffix, "%Y-%m-%d").date()
        except ValueError:
            errors.append(f"{name}: invalid expiry format, expected {EXP_PREFIX}YYYY-MM-DD")
            continue
        if expiry < TODAY:
            errors.append(f"{name}: expired on {expiry}")
    if errors:
        sys.stderr.write("Allowlist validation failed:\n" + "\n".join(errors) + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
