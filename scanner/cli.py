"""Command-line entry point for the Serverless Guardrails scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List

from .result import ScanResult, format_summary_table
from .rules import Rule, ScanContext
from .rules.env_secret import EnvSecretRule
from .rules.iam_leastpriv import IamLeastPrivilegeRule
from .rules.vpc_egress import VpcEgressRule
from .utils import iac

DEFAULT_TEMPLATE = "templates/app-sam.yaml"
DEFAULT_SOURCE_DIRS = ("functions",)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static analysis scanner for Serverless Guardrails",
    )
    parser.add_argument(
        "--template",
        default=DEFAULT_TEMPLATE,
        help="Path to the SAM/CloudFormation template to scan.",
    )
    parser.add_argument(
        "--source",
        "-s",
        dest="source_dirs",
        action="append",
        default=[],
        help="Directory containing Lambda source to review (repeatable).",
    )
    parser.add_argument(
        "--source-dir",
        dest="source_dirs",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Report format for file output (defaults to json).",
    )
    parser.add_argument(
        "--out",
        "--output",
        dest="output_path",
        type=str,
        default=None,
        help="Path to write the structured report (e.g., artifacts/scan.json).",
    )
    parser.add_argument(
        "--fail-on-empty",
        action="store_true",
        help="Fail the scan if the template cannot be parsed.",
    )
    return parser


def load_rules() -> List[Rule]:
    return [
        EnvSecretRule(),
        IamLeastPrivilegeRule(),
        VpcEgressRule(),
    ]


def run_scan(template_path: str, source_paths: Iterable[str], fail_on_empty: bool = False) -> ScanResult:
    template = iac.load_template(Path(template_path))
    if template is None:
        if fail_on_empty:
            raise SystemExit(f"Failed to load template: {template_path}")
        template = {}
    context = ScanContext(template=template, source_paths=tuple(source_paths))
    result = ScanResult()
    for rule in load_rules():
        rule.scan(context, result)
    return result


def write_output(result: ScanResult, output_path: str | None, report_format: str) -> None:
    summary = format_summary_table(result)
    print(summary)

    if report_format == "json":
        payload = json.dumps(result.to_dict(), indent=2)
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(payload, encoding="utf-8")
            print(f"\nReport written to {output_path}")
        else:
            print("\nJSON Report")
            print(payload)


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    sources = args.source_dirs or list(DEFAULT_SOURCE_DIRS)
    result = run_scan(args.template, sources, fail_on_empty=args.fail_on_empty)
    write_output(result, args.output_path, args.format)
    return result.exit_code()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
