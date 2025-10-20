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


def test_vpc_rule_detects_public_subnet_via_route_association():
    template = {
        "Resources": {
            "PublicSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": "vpc-123",
                    "CidrBlock": "10.0.0.0/24",
                    "MapPublicIpOnLaunch": False,
                },
            },
            "PublicRouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {"VpcId": "vpc-123"},
            },
            "PublicRoute": {
                "Type": "AWS::EC2::Route",
                "Properties": {
                    "RouteTableId": {"Ref": "PublicRouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-123456",
                },
            },
            "PublicSubnetAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "PublicSubnet"},
                    "RouteTableId": {"Ref": "PublicRouteTable"},
                },
            },
            "RestrictedSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Restricted egress",
                    "VpcId": "vpc-123",
                    "SecurityGroupEgress": [
                        {"IpProtocol": "tcp", "CidrIp": "10.0.0.0/8", "FromPort": 443, "ToPort": 443}
                    ],
                },
            },
            "MyFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "VpcConfig": {
                        "SubnetIds": [{"Ref": "PublicSubnet"}],
                        "SecurityGroupIds": [{"Ref": "RestrictedSG"}],
                    }
                },
            },
        }
    }

    context = ScanContext(template=template, source_paths=())
    result = ScanResult()

    VpcEgressRule().scan(context, result)

    assert result.summary.high == 1
    assert any("Subnet:PublicSubnet" in finding.path for finding in result.findings)


def test_vpc_rule_detects_private_nat_route():
    template = {
        "Resources": {
            "PrivateSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": "vpc-123",
                    "CidrBlock": "10.0.1.0/24",
                    "MapPublicIpOnLaunch": False,
                    "Tags": [{"Key": "Network", "Value": "Private"}],
                },
            },
            "PrivateRouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {"VpcId": "vpc-123"},
            },
            "NatRoute": {
                "Type": "AWS::EC2::Route",
                "Properties": {
                    "RouteTableId": {"Ref": "PrivateRouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "NatGatewayId": "nat-abc123",
                },
            },
            "PrivateSubnetAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "PrivateSubnet"},
                    "RouteTableId": {"Ref": "PrivateRouteTable"},
                },
            },
            "RestrictedSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Restricted egress",
                    "VpcId": "vpc-123",
                    "SecurityGroupEgress": [
                        {"IpProtocol": "tcp", "CidrIp": "10.0.0.0/8", "FromPort": 443, "ToPort": 443}
                    ],
                },
            },
            "MyFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "VpcConfig": {
                        "SubnetIds": [{"Ref": "PrivateSubnet"}],
                        "SecurityGroupIds": [{"Ref": "RestrictedSG"}],
                    }
                },
            },
        }
    }

    context = ScanContext(template=template, source_paths=())
    result = ScanResult()

    VpcEgressRule().scan(context, result)

    assert result.summary.medium == 1
    assert any("Private subnet egresses through NAT Gateway" in finding.title for finding in result.findings)
