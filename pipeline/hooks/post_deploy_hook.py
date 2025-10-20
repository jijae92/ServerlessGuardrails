"""Pipeline post-deploy hook to validate deployed stack network/iam posture."""

from __future__ import annotations

import json
import os

import boto3

STACK_NAME = os.environ.get("STACK_NAME", "serverless-guardrails-demo")
GUIDE_URL = os.environ.get(
    "GUIDE_URL",
    "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/security.html",
)

CFN = boto3.client("cloudformation")
EC2 = boto3.client("ec2")


def _describe_security_group(group_id: str) -> dict:
    response = EC2.describe_security_groups(GroupIds=[group_id])
    return response["SecurityGroups"][0]


def handler(event, _context):
    job = event["CodePipeline.job"]
    job_id = job["id"]
    client = boto3.client("codepipeline")

    try:
        resources = CFN.describe_stack_resources(StackName=STACK_NAME)["StackResources"]
    except Exception as exc:  # pylint: disable=broad-except
        client.put_job_failure_result(
            jobId=job_id,
            failureDetails={
                "type": "JobFailed",
                "message": f"Unable to describe stack {STACK_NAME}: {exc}",
            },
        )
        return

    findings = []
    sg_ids = [res["PhysicalResourceId"] for res in resources if res["ResourceType"] == "AWS::EC2::SecurityGroup"]
    for sg_id in sg_ids:
        sg = _describe_security_group(sg_id)
        for permission in sg.get("IpPermissionsEgress", []):
            for rng in permission.get("IpRanges", []):
                cidr = rng.get("CidrIp")
                if cidr == "0.0.0.0/0":
                    findings.append(f"SecurityGroup {sg_id} allows 0.0.0.0/0 outbound")

    if findings:
        message = "Post-deploy validation failed:\n" + "\n".join(findings) + f"\nRemediation: {GUIDE_URL}"
        client.put_job_failure_result(
            jobId=job_id,
            failureDetails={
                "type": "JobFailed",
                "message": message,
            },
        )
        return

    summary = {
        "stack": STACK_NAME,
        "validatedSecurityGroups": sg_ids,
    }
    client.put_job_success_result(jobId=job_id, executionDetails={"summary": json.dumps(summary)})
*** End of File
