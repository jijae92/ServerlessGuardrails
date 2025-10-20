"""Safe Lambda function demonstrating best practices."""

import json
import os

try:
    import boto3  # type: ignore
except ImportError:  # pragma: no cover - runtime dependency
    boto3 = None


def _fetch_secret(secret_arn: str) -> str:
    """Fetch sensitive data from Secrets Manager at runtime."""

    if not secret_arn or boto3 is None:
        return "retrieved-at-runtime"

    client = boto3.client("secretsmanager")
    try:
        response = client.get_secret_value(SecretId=secret_arn)
    except Exception:  # pragma: no cover - runtime failure path
        return "unavailable"
    return response.get("SecretString", "unavailable")


def handler(event, context):  # pragma: no cover - demo function
    secret_arn = os.environ.get("SECRET_ARN", "")
    payload = {
        "message": "Secret resolved securely at runtime",
        "apiKey": _fetch_secret(secret_arn),
    }
    return {
        "statusCode": 200,
        "body": json.dumps(payload),
    }
