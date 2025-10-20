"""Pipeline pre-deploy hook that re-validates scanner output."""

from __future__ import annotations

import json
import os
import tempfile
import zipfile

import boto3


FAILURE_GUIDE_URL = os.environ.get(
    "GUIDE_URL",
    "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/security.html",
)

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _extract_artifact(job_data: dict, target_path: str) -> dict:
    credentials = job_data["artifactCredentials"]
    session = boto3.Session(
        aws_access_key_id=credentials["accessKeyId"],
        aws_secret_access_key=credentials["secretAccessKey"],
        aws_session_token=credentials["sessionToken"],
        region_name=os.environ.get("AWS_REGION"),
    )
    s3_client = session.client("s3")

    artifact = job_data["inputArtifacts"][0]
    bucket = artifact["location"]["s3Location"]["bucketName"]
    key = artifact["location"]["s3Location"]["objectKey"]

    with tempfile.NamedTemporaryFile() as tmp_file:
        s3_client.download_file(bucket, key, tmp_file.name)
        with zipfile.ZipFile(tmp_file.name) as zipped:
            with zipped.open(target_path) as scan_file:
                return json.loads(scan_file.read().decode("utf-8"))


def _top_findings(report: dict, limit: int = 10) -> list[str]:
    findings = report.get("findings", [])
    ordered = sorted(
        findings,
        key=lambda item: ORDER.index(item.get("severity", "INFO")) if item.get("severity") in ORDER else len(ORDER),
    )
    highlights = []
    for item in ordered[:limit]:
        highlights.append(
            f"[{item.get('severity')}] {item.get('id')} {item.get('title')} -> {item.get('resource')} ({item.get('path')})"
        )
    return highlights


def handler(event, _context):
    job = event["CodePipeline.job"]
    job_id = job["id"]
    data = job["data"]

    client = boto3.client("codepipeline")

    try:
        report = _extract_artifact(data, "artifacts/scan.json")
    except Exception as exc:  # pylint: disable=broad-except
        client.put_job_failure_result(
            jobId=job_id,
            failureDetails={
                "type": "JobFailed",
                "message": f"Failed to read scan.json: {exc}",
            },
        )
        return

    passed = bool(report.get("passed"))
    summary = report.get("summary", {})
    highlights = _top_findings(report)
    message_lines = [
        "Scanner verification (pre-deploy hook)",
        f"Passed: {passed}",
        f"Summary: {summary}",
    ]
    if highlights:
        message_lines.append("Highlights:")
        message_lines.extend(highlights)
    message_lines.append(f"Remediation: {FAILURE_GUIDE_URL}")
    message = "\n".join(message_lines)

    if not passed:
        client.put_job_failure_result(
            jobId=job_id,
            failureDetails={
                "type": "JobFailed",
                "message": message,
            },
        )
        return

    client.put_job_success_result(jobId=job_id, executionDetails={"summary": "Scanner re-validation successful"})
*** End of File
