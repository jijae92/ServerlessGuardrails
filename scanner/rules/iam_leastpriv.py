"""Detect overly permissive IAM policies in SAM/CloudFormation templates."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from scanner.result import Finding, ScanResult
from scanner.severity import Severity

from . import Rule, ScanContext

SECURITY_CRITICAL_PREFIXES = (
    "*",
    "iam:",
    "kms:",
    "sts:",
    "organizations:",
)
CONDITION_SENSITIVE_ACTIONS = {
    "iam:PassRole",
    "iam:CreateUser",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "kms:CreateGrant",
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:ScheduleKeyDeletion",
    "s3:PutObject",
    "s3:GetObject",
    "logs:PutRetentionPolicy",
    "lambda:AddPermission",
    "lambda:UpdateFunctionCode",
}
WILDCARD_RESOURCE_PATTERN = re.compile(r"[*]\Z|:.*[*]")

BASE_FINDING_ID = "IAM"

MINIMUM_POLICY_ACTIONS = [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
]


class IamLeastPrivilegeRule:
    """Warn when IAM statements violate least privilege guidance."""

    name = "iam_leastpriv"

    def __init__(self) -> None:
        self._counter = 0

    def scan(self, context: ScanContext, result: ScanResult) -> None:
        resources = context.template.get("Resources", {}) if context.template else {}
        for logical_id, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get("Type")
            if resource_type not in {"AWS::IAM::Role", "AWS::IAM::Policy", "AWS::Serverless::Function"}:
                continue
            for statement, path_suffix in self._extract_statements(resource_type, logical_id, resource):
                finding = self._evaluate_statement(resource_type, logical_id, statement, path_suffix)
                if finding:
                    result.add_finding(finding)

    # ------------------------------------------------------------------
    # Statement extraction helpers
    # ------------------------------------------------------------------
    def _extract_statements(
        self,
        resource_type: str,
        logical_id: str,
        resource: Dict[str, Any],
    ) -> Iterator[Tuple[Dict[str, Any], str]]:
        props = resource.get("Properties") or {}

        if resource_type == "AWS::Serverless::Function":
            policies = props.get("Policies") or []
            if isinstance(policies, dict):
                policies = [policies]
            for index, policy in enumerate(policies):
                if isinstance(policy, str):
                    continue  # managed policies, not analyzable statically here
                statements = policy.get("Statement") if isinstance(policy, dict) else None
                yield from self._iter_statements(statements, f"Policies[{index}]")
        elif resource_type in {"AWS::IAM::Role"}:
            policies = props.get("Policies") or []
            for index, policy in enumerate(policies):
                statements = policy.get("PolicyDocument", {}).get("Statement") if isinstance(policy, dict) else None
                suffix = f"Policies[{index}].PolicyDocument"
                yield from self._iter_statements(statements, suffix)
            assume_doc = props.get("AssumeRolePolicyDocument")
            yield from self._iter_statements(assume_doc.get("Statement") if isinstance(assume_doc, dict) else None, "AssumeRolePolicyDocument")
        elif resource_type == "AWS::IAM::Policy":
            policy_doc = props.get("PolicyDocument") or {}
            yield from self._iter_statements(policy_doc.get("Statement"), "PolicyDocument")

    def _iter_statements(self, statements: Any, suffix: str) -> Iterator[Tuple[Dict[str, Any], str]]:
        if statements is None:
            return
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return
        for idx, statement in enumerate(statements):
            if isinstance(statement, dict):
                yield statement, f"{suffix}.Statement[{idx}]"

    # ------------------------------------------------------------------
    # Evaluation logic
    # ------------------------------------------------------------------
    def _evaluate_statement(
        self,
        resource_type: str,
        logical_id: str,
        statement: Dict[str, Any],
        path_suffix: str,
    ) -> Optional[Finding]:
        effect = str(statement.get("Effect", "Allow"))
        if effect.upper() != "ALLOW":
            return None

        actions = self._ensure_list(statement.get("Action"))
        resources = self._ensure_list(statement.get("Resource"))
        condition = statement.get("Condition")

        severity: Optional[Severity] = None
        issue_detail: Optional[str] = None

        if self._has_critical_action(actions):
            severity = Severity.CRITICAL
            issue_detail = "Action allows wildcard or security-critical service scope"
        elif self._has_wildcard_resource(resources):
            severity = Severity.HIGH
            issue_detail = "Resource is wildcarded"

        if severity is None and self._needs_condition(actions, condition):
            severity = Severity.MEDIUM
            issue_detail = "High-risk action without condition"

        if severity is None:
            return None

        finding_id = self._next_id()
        recommendation = self._build_recommendation(logical_id)

        path = self._format_path(logical_id, path_suffix)
        title = "IAM least privilege violation"
        description = self._build_description(issue_detail, actions, resources, condition)

        return Finding(
            id=finding_id,
            title=title,
            resource=f"{resource_type} {logical_id}",
            path=path,
            severity=severity,
            rule=self.name,
            recommendation=description + "\n" + recommendation,
        )

    def _has_critical_action(self, actions: List[str]) -> bool:
        for action in actions:
            action_lower = action.lower()
            for prefix in SECURITY_CRITICAL_PREFIXES:
                if action_lower.startswith(prefix):
                    return True
        return False

    def _has_wildcard_resource(self, resources: List[str]) -> bool:
        for resource in resources:
            if WILDCARD_RESOURCE_PATTERN.search(str(resource)):
                return True
        return False

    def _needs_condition(self, actions: List[str], condition: Any) -> bool:
        if condition:
            return False
        for action in actions:
            if action.lower() in {act.lower() for act in CONDITION_SENSITIVE_ACTIONS}:
                return True
            for sensitive_prefix in ("iam:", "kms:"):
                if action.lower().startswith(sensitive_prefix):
                    return True
        return False

    def _ensure_list(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    def _format_path(self, logical_id: str, suffix: str) -> str:
        return f"templates/app-sam.yaml:Resources/{logical_id}/{suffix}"

    def _build_description(
        self,
        issue_detail: str,
        actions: List[str],
        resources: List[str],
        condition: Any,
    ) -> str:
        fragments = [issue_detail]
        fragments.append(f"Actions: {actions}")
        fragments.append(f"Resources: {resources or ['*']}")
        if not condition:
            fragments.append("Condition: none")
        return "; ".join(fragments)

    def _build_recommendation(self, logical_id: str) -> str:
        policy_snippet = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": MINIMUM_POLICY_ACTIONS,
                        "Resource": [
                            f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/{logical_id}:*"
                        ],
                    }
                ],
            },
            indent=2,
        )
        guidance = (
            "Adopt least privilege by scoping actions/resources and applying conditions. "
            "Reference NIST SP 800-53 AC-6, ISO/IEC 27001 A.9, and AWS Well-Architected (Security Pillar – IAM)."
        )
        howto = (
            "Example least-privilege policy:\n" + policy_snippet + "\n" +
            "Use AWS managed policies sparingly and prefer function-specific grants."
        )
        return guidance + " " + howto

    def _next_id(self) -> str:
        self._counter += 1
        return f"{BASE_FINDING_ID}{self._counter:03d}"


def get_rule() -> Rule:
    return IamLeastPrivilegeRule()
