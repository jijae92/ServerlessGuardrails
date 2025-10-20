"""Intentionally vulnerable Lambda function used for scanner demos."""

import os


# Hardcoded credentials and tokens intentionally left to exercise the scanner.
HARDCODED_ACCESS_KEY = "AKIAEXAMPLE1234567890AB"
HARDCODED_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzZXJ2ZXJsZXNzLWd1YXJkcmFpbHMiLCJhdWQiOiJ1c2VyIn0."
    "ABCDEFGHIJKLMNOPQRSTUVWX"
)


def handler(event, context):  # pragma: no cover - demo function
    api_key = os.environ.get("API_KEY", HARDCODED_ACCESS_KEY)
    secret_token = os.environ.get("SECRET_TOKEN", HARDCODED_JWT)

    return {
        "message": "This function leaks secrets via environment variables and code constants.",
        "api_key": api_key,
        "token": secret_token,
    }
