from scanner.result import ScanResult
from scanner.rules import ScanContext
from scanner.rules.vpc_egress import VpcEgressRule


def test_vpc_rule_requires_security_group_ids():
    template = {
        "Resources": {
            "MyFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "VpcConfig": {}
                },
            }
        }
    }

    context = ScanContext(template=template, source_paths=())
    result = ScanResult()

    VpcEgressRule().scan(context, result)

    assert result.summary.medium == 1
    assert result.findings[0].rule == "vpc_egress"


def test_vpc_rule_flags_open_sg_egress():
    template = {
        "Resources": {
            "MySecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Open egress",
                    "VpcId": "vpc-123456",
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
            },
            "MyFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "VpcConfig": {
                        "SubnetIds": ["SubnetA"],
                        "SecurityGroupIds": ["MySecurityGroup"],
                    }
                },
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": "vpc-123456",
                    "CidrBlock": "10.0.0.0/24",
                    "MapPublicIpOnLaunch": False,
                },
            },
        }
    }

    context = ScanContext(template=template, source_paths=())
    result = ScanResult()

    VpcEgressRule().scan(context, result)

    assert result.summary.high == 1
    assert result.findings[0].severity.value == "HIGH"
