"""Detect hardcoded secrets in Lambda environment variables and source code."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from scanner.result import Finding, ScanResult
from scanner.severity import Severity
from scanner.utils import iter_code_files, read_text_file

from . import Rule, ScanContext

KEY_PATTERN = re.compile(r"(?i)(secret|token|api[_-]?key|password|passwd|access[_-]?key|private|key|credential|auth)")
LONG_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_\-]{24,}")
AWS_ACCESS_KEY_PATTERN = re.compile(r"(?:A3T|AKIA|ASIA)[0-9A-Z]{16}")
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+")
PLACEHOLDER_HINTS = ("dummy", "example", "placeholder", "sample", "retrieved", "deployment")
ALLOWLIST_FILENAME = ".guardrails-allow.json"


class EnvSecretRule:
    """Flag suspicious environment secrets across IaC and code."""

    name = "env_secret"

    def __init__(self, allowlist_path: str = ALLOWLIST_FILENAME) -> None:
        self._allowlist_path = Path(allowlist_path)
        self._cached_allow_env_names: Optional[Set[str]] = None
        self._finding_counter = 0

    def scan(self, context: ScanContext, result: ScanResult) -> None:
        allow_env_names = self._load_allow_env_names()
        self._scan_template(context, result, allow_env_names)
        self._scan_source(context, result, allow_env_names)

    # ------------------------------------------------------------------
    # Template analysis
    # ------------------------------------------------------------------
    def _scan_template(self, context: ScanContext, result: ScanResult, allow_env_names: Set[str]) -> None:
        resources = context.template.get("Resources", {}) if context.template else {}
        for logical_id, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get("Type")
            if resource_type not in {"AWS::Serverless::Function", "AWS::Lambda::Function"}:
                continue
            environment = self._extract_environment(resource)
            for key, value in environment.items():
                if key.upper() in allow_env_names:
                    continue
                finding = self._evaluate_candidate(
                    name=key,
                    value=value,
                    resource=f"{resource_type} {logical_id}",
                    path=self._build_template_path(logical_id, key),
                    location_hint="template",
                    allow_name_only=True,
                )
                if finding:
                    result.add_finding(finding)

    def _extract_environment(self, resource: Dict[str, Any]) -> Dict[str, str]:
        props = resource.get("Properties") or {}
        environment = props.get("Environment") or {}
        variables = environment.get("Variables") or {}
        if isinstance(variables, dict):
            return {k: v for k, v in variables.items() if isinstance(v, str)}
        return {}

    def _build_template_path(self, logical_id: str, key: str) -> str:
        return (
            "templates/app-sam.yaml:Resources/"
            f"{logical_id}/Properties/Environment/Variables/{key}"
        )

    # ------------------------------------------------------------------
    # Source analysis
    # ------------------------------------------------------------------
    def _scan_source(self, context: ScanContext, result: ScanResult, allow_env_names: Set[str]) -> None:
        for root in context.source_paths:
            for path in iter_code_files([root], extensions=(".py",)):
                source = read_text_file(path)
                if not source:
                    continue
                try:
                    tree = ast.parse(source)
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        literal = node.value
                        candidate_name = literal
                        if candidate_name.upper() in allow_env_names:
                            continue
                        finding = self._evaluate_candidate(
                            name=candidate_name,
                            value=candidate_name,
                            resource=f"PythonSource {path}",
                            path=f"{path}:{getattr(node, 'lineno', 1)}",
                            location_hint="code",
                            allow_name_only=False,
                        )
                        if finding:
                            result.add_finding(finding)

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------
    def _evaluate_candidate(
        self,
        name: str,
        value: str,
        resource: str,
        path: str,
        location_hint: str,
        allow_name_only: bool,
    ) -> Optional[Finding]:
        name_match = KEY_PATTERN.search(name)
        value_indicator, severity = self._classify_value(value, location_hint)

        if not value_indicator and not (allow_name_only and name_match):
            return None

        if value_indicator and severity is None:
            severity = Severity.HIGH
        elif not value_indicator:
            severity = Severity.LOW

        finding_id = self._next_finding_id()
        title = self._build_title(value_indicator, location_hint)
        recommendation = self._build_recommendation()

        return Finding(
            id=finding_id,
            title=title,
            resource=resource,
            path=path,
            severity=severity,
            rule=self.name,
            recommendation=recommendation,
        )

    def _classify_value(self, value: str, location_hint: str) -> Tuple[Optional[str], Optional[Severity]]:
        value = value or ""
        indicator = None
        severity: Optional[Severity] = None

        if AWS_ACCESS_KEY_PATTERN.search(value):
            indicator = "aws_access_key"
            severity = Severity.HIGH
        elif JWT_PATTERN.search(value):
            indicator = "jwt"
            severity = Severity.HIGH
        elif LONG_TOKEN_PATTERN.search(value):
            indicator = "long_token"
            severity = Severity.HIGH

        if indicator:
            lowered = value.lower()
            if any(hint in lowered for hint in PLACEHOLDER_HINTS):
                severity = Severity.LOW

        if not indicator:
            return None, None
        if location_hint == "code" and severity == Severity.HIGH:
            severity = Severity.HIGH
        return indicator, severity

    def _build_title(self, indicator: Optional[str], location_hint: str) -> str:
        if location_hint == "code":
            return "Possible secret literal in source code"
        if indicator:
            return "Hardcoded secret value in Lambda environment"
        return "Suspicious environment variable naming"

    def _build_recommendation(self) -> str:
        return (
            "Move sensitive values to AWS Secrets Manager or SSM Parameter Store with KMS encryption. "
            "Reference them via Ref/ImportValue or {{resolve:secretsmanager:...}} in templates, and load them at runtime instead of hardcoding."
        )

    def _next_finding_id(self) -> str:
        self._finding_counter += 1
        return f"ENV{self._finding_counter:03d}"

    # ------------------------------------------------------------------
    # Allowlist helpers
    # ------------------------------------------------------------------
    def _load_allow_env_names(self) -> Set[str]:
        if self._cached_allow_env_names is not None:
            return self._cached_allow_env_names
        env_names: Set[str] = set()
        if self._allowlist_path.exists():
            try:
                data = json.loads(self._allowlist_path.read_text(encoding="utf-8"))
                names = data.get("env_names", [])
                if isinstance(names, (list, tuple, set)):
                    env_names = {str(name).upper() for name in names}
                elif isinstance(names, str):
                    env_names = {names.upper()}
            except (json.JSONDecodeError, OSError):
                env_names = set()
        self._cached_allow_env_names = env_names
        return env_names


def get_rule() -> Rule:
    return EnvSecretRule()
