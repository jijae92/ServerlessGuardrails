from scanner.result import ScanResult
from scanner.rules import ScanContext
from scanner.rules.env_secret import EnvSecretRule


def test_env_secret_detects_hardcoded_value():
    template = {
        "Resources": {
            "VulnerableFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Environment": {
                        "Variables": {
                            "API_KEY": "sk_live_test_secret_token_value_123456",
                        }
                    }
                },
            }
        }
    }

    context = ScanContext(template=template, source_paths=())
    result = ScanResult()

    EnvSecretRule().scan(context, result)

    assert result.summary.high == 1
    assert not result.passed
    assert result.findings[0].id == "ENV001"


def test_env_secret_allowlist_skips_config(tmp_path):
    allowlist = tmp_path / ".guardrails-allow.json"
    allowlist.write_text('{"env_names": ["API_KEY"]}', encoding="utf-8")

    template = {
        "Resources": {
            "SafeFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Environment": {
                        "Variables": {
                            "API_KEY": "placeholder_value",
                        }
                    }
                },
            }
        }
    }

    context = ScanContext(template=template, source_paths=())
    result = ScanResult()

    rule = EnvSecretRule(allowlist_path=str(allowlist))
    rule.scan(context, result)

    assert result.summary.high == 0
    assert result.summary.medium == 0
    assert result.summary.low == 0
