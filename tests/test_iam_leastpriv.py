from scanner.result import ScanResult
from scanner.rules import ScanContext
from scanner.rules.iam_leastpriv import IamLeastPrivilegeRule


def run_rule(template):
    context = ScanContext(template=template, source_paths=())
    result = ScanResult()
    IamLeastPrivilegeRule().scan(context, result)
    return result


def test_wildcard_action_is_critical():
    template = {
        "Resources": {
            "FunctionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [
                        {
                            "PolicyName": "Insecure",
                            "PolicyDocument": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "*",
                                        "Resource": "arn:aws:s3:::my-bucket/*",
                                    }
                                ]
                            },
                        }
                    ]
                },
            }
        }
    }

    result = run_rule(template)

    assert result.summary.critical == 1
    assert result.exit_code() == 2
    assert result.findings[0].severity.value == "CRITICAL"


def test_wildcard_resource_is_high():
    template = {
        "Resources": {
            "FunctionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [
                        {
                            "PolicyName": "WideResource",
                            "PolicyDocument": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject"],
                                        "Resource": "*",
                                    }
                                ]
                            },
                        }
                    ]
                },
            }
        }
    }

    result = run_rule(template)

    assert result.summary.high == 1
    assert result.findings[0].severity.value == "HIGH"


def test_sensitive_action_without_condition_is_medium():
    template = {
        "Resources": {
            "FunctionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [
                        {
                            "PolicyName": "NeedsCondition",
                            "PolicyDocument": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "s3:PutObject",
                                        "Resource": "arn:aws:s3:::secure-bucket/sensitive-object",
                                    }
                                ]
                            },
                        }
                    ]
                },
            }
        }
    }

    result = run_rule(template)

    assert result.summary.medium == 1
    assert result.findings[0].severity.value == "MEDIUM"
