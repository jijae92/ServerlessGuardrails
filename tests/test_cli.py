import json
from pathlib import Path

from scanner import cli


def test_cli_generates_json_report(tmp_path, capsys):
    output_path = tmp_path / "scan.json"

    exit_code = cli.main(
        [
            "--template",
            "templates/app-sam.yaml",
            "--source",
            "functions/vulnerable",
            "--out",
            str(output_path),
        ]
    )

    captured = capsys.readouterr()
    assert "Scan Summary" in captured.out
    assert exit_code == 2  # High/critical findings from vulnerable template
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["summary"]["high"] >= 1
    assert data["passed"] is False


def test_cli_passes_on_clean_template(tmp_path, capsys):
    template_path = tmp_path / "clean.yaml"
    template_path.write_text(
        """
Resources:
  SafeFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: ../functions/safe/
      Handler: app.handler
      Runtime: python3.11
        """.strip()
    )

    output_path = tmp_path / "clean.json"
    exit_code = cli.main(
        [
            "--template",
            str(template_path),
            "--source",
            "functions/safe",
            "--out",
            str(output_path),
        ]
    )

    captured = capsys.readouterr()
    assert "Scan Summary" in captured.out
    assert exit_code == 0
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["summary"]["high"] == 0
    assert data["passed"] is True
