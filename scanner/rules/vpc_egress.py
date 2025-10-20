"""Detect risky Lambda VPC egress configurations in SAM/CloudFormation templates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set

from scanner.result import Finding, ScanResult
from scanner.severity import Severity

from . import Rule, ScanContext

CIDR_ANY = "0.0.0.0/0"
FINDING_PREFIX = "VPC"
PRIVATE_TAG_KEY = "Network"
PRIVATE_TAG_VALUE = "Private"

RISK_GUIDANCE = (
    "Restrict Lambda egress paths. Use interface VPC endpoints for AWS APIs (Secrets Manager, SSM, STS), "
    "apply egress allow-lists in security groups or AWS Network Firewall, and favor proxy-controlled NAT flows. "
    "Aligned controls: NIST SP 800-53 SC-7, AWS Well-Architected Security – Network Controls."
)


@dataclass
class SubnetMetadata:
    logical_id: str
    is_public: bool
    is_private_tagged: bool


@dataclass
class RouteMetadata:
    destination: str
    target_type: str


@dataclass
class SecurityGroupRule:
    cidr: str
    protocol: str


class VpcEgressRule:
    """Ensure Lambda VPC connectivity is constrained to trusted egress paths."""

    name = "vpc_egress"

    def __init__(self) -> None:
        self._counter = 0

    def scan(self, context: ScanContext, result: ScanResult) -> None:
        template = context.template or {}
        resources = template.get("Resources", {})
        subnets = self._collect_subnets(resources)
        subnet_routes = self._collect_routes(resources)
        sg_rules = self._collect_security_groups(resources)
        vpc_endpoints = self._collect_vpc_endpoints(resources)

        for logical_id, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            if resource.get("Type") not in {"AWS::Serverless::Function", "AWS::Lambda::Function"}:
                continue
            vpc_config = self._get_vpc_config(resource)
            if vpc_config is None:
                continue

            subnet_ids = self._ensure_list(vpc_config.get("SubnetIds"))
            security_group_ids = self._ensure_list(vpc_config.get("SecurityGroupIds"))

            findings = []
            if not security_group_ids:
                findings.append(
                    self._build_finding(
                        Severity.MEDIUM,
                        logical_id,
                        "VpcConfig",
                        "No security group attached to Lambda VPC config",
                        "Attach a restrictive security group with explicit egress allow-list before deployment.",
                    )
                )
            findings.extend(self._check_subnets(logical_id, subnet_ids, subnets, subnet_routes))
            findings.extend(self._check_security_groups(logical_id, security_group_ids, sg_rules))
            findings.extend(self._check_endpoints(logical_id, subnet_ids, vpc_endpoints))

            for finding in findings:
                result.add_finding(finding)

    # ------------------------------------------------------------------
    # Collection helpers
    # ------------------------------------------------------------------
    def _collect_subnets(self, resources: Dict[str, Any]) -> Dict[str, SubnetMetadata]:
        subnets: Dict[str, SubnetMetadata] = {}
        for logical_id, resource in resources.items():
            if resource.get("Type") != "AWS::EC2::Subnet":
                continue
            props = resource.get("Properties", {})
            tags = {tag.get("Key"): tag.get("Value") for tag in props.get("Tags", []) if isinstance(tag, dict)}
            is_public = bool(props.get("MapPublicIpOnLaunch")) or tags.get("SubnetType") == "Public"
            is_private_tagged = tags.get(PRIVATE_TAG_KEY) == PRIVATE_TAG_VALUE
            subnets[logical_id] = SubnetMetadata(logical_id, is_public, is_private_tagged)
        return subnets

    def _collect_routes(self, resources: Dict[str, Any]) -> Dict[str, List[RouteMetadata]]:
        routes_by_table: Dict[str, List[RouteMetadata]] = {}
        associations: Dict[str, Set[str]] = {}

        for logical_id, resource in resources.items():
            resource_type = resource.get("Type")
            if resource_type == "AWS::EC2::Route":
                props = resource.get("Properties", {})
                route_table_id = self._normalize_reference(props.get("RouteTableId"))
                if not route_table_id:
                    continue
                destination = props.get("DestinationCidrBlock")
                if not isinstance(destination, str):
                    continue
                target_type = ""
                if props.get("GatewayId"):
                    target_type = "igw"
                elif props.get("NatGatewayId"):
                    target_type = "nat"
                elif props.get("TransitGatewayId"):
                    target_type = "tgw"
                routes_by_table.setdefault(route_table_id, []).append(RouteMetadata(destination, target_type))
            elif resource_type == "AWS::EC2::SubnetRouteTableAssociation":
                props = resource.get("Properties", {})
                subnet_id = self._normalize_reference(props.get("SubnetId"))
                route_table_id = self._normalize_reference(props.get("RouteTableId"))
                if subnet_id and route_table_id:
                    associations.setdefault(subnet_id, set()).add(route_table_id)

        subnet_routes: Dict[str, List[RouteMetadata]] = {}
        for subnet_id, table_ids in associations.items():
            collected: List[RouteMetadata] = []
            for table_id in table_ids:
                collected.extend(routes_by_table.get(table_id, []))
            subnet_routes[subnet_id] = collected

        return subnet_routes

    def _collect_security_groups(self, resources: Dict[str, Any]) -> Dict[str, List[SecurityGroupRule]]:
        sg_rules: Dict[str, List[SecurityGroupRule]] = {}
        for logical_id, resource in resources.items():
            if resource.get("Type") != "AWS::EC2::SecurityGroup":
                continue
            props = resource.get("Properties", {})
            egress_rules = props.get("SecurityGroupEgress", []) or []
            sg_rules[logical_id] = [
                SecurityGroupRule(
                    cidr=str(rule.get("CidrIp", CIDR_ANY)),
                    protocol=str(rule.get("IpProtocol", "-1")),
                )
                for rule in egress_rules
                if isinstance(rule, dict)
            ]
        return sg_rules

    def _collect_vpc_endpoints(self, resources: Dict[str, Any]) -> List[str]:
        endpoints: List[str] = []
        for logical_id, resource in resources.items():
            if resource.get("Type") != "AWS::EC2::VPCEndpoint":
                continue
            props = resource.get("Properties", {})
            service_name = props.get("ServiceName")
            if isinstance(service_name, str):
                endpoints.append(service_name.lower())
        return endpoints

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------
    def _check_subnets(
        self,
        function_id: str,
        subnet_ids: Iterable[str],
        subnets: Dict[str, SubnetMetadata],
        subnet_routes: Dict[str, List[RouteMetadata]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        for subnet_id in subnet_ids:
            metadata = subnets.get(subnet_id)
            if not metadata:
                continue
            routes = subnet_routes.get(subnet_id, [])
            has_internet_gateway = any(route.destination == CIDR_ANY and route.target_type == "igw" for route in routes)
            has_nat_gateway = any(route.destination == CIDR_ANY and route.target_type == "nat" for route in routes)

            if metadata.is_public or has_internet_gateway:
                findings.append(
                    self._build_finding(
                        Severity.HIGH,
                        function_id,
                        f"Subnet:{subnet_id}",
                        "Lambda connected to public subnet",
                        "Subnet maps public IPs or routes 0.0.0.0/0 via an Internet Gateway.",
                    )
                )
            elif metadata.is_private_tagged and has_nat_gateway:
                findings.append(
                    self._build_finding(
                        Severity.MEDIUM,
                        function_id,
                        f"Subnet:{subnet_id}",
                        "Private subnet egresses through NAT Gateway",
                        "Private-tagged subnet still allows 0.0.0.0/0 via NAT Gateway; tighten egress controls.",
                    )
                )
        return findings

    def _check_security_groups(
        self,
        function_id: str,
        sg_ids: Iterable[str],
        sg_rules: Dict[str, List[SecurityGroupRule]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        for sg_id in sg_ids:
            for rule in sg_rules.get(sg_id, []):
                if rule.cidr == CIDR_ANY or rule.cidr.endswith("/0"):
                    findings.append(
                        self._build_finding(
                            Severity.HIGH,
                            function_id,
                            f"SecurityGroup:{sg_id}",
                            "Security group allows unrestricted outbound access",
                            "Egress rule permits all destinations; restrict to approved CIDRs or interface endpoints.",
                        )
                    )
                    break
        return findings

    def _check_endpoints(
        self,
        function_id: str,
        subnet_ids: Iterable[str],
        vpc_endpoints: List[str],
    ) -> List[Finding]:
        if not subnet_ids:
            return []
        if vpc_endpoints:
            return []
        return [
            self._build_finding(
                Severity.INFO,
                function_id,
                "VpcConfig",
                "No VPC endpoints defined for private egress",
                "Consider interface endpoints or private NAT/proxy controls for external API access.",
            )
        ]

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------
    def _build_finding(
        self,
        severity: Severity,
        function_id: str,
        path: str,
        title: str,
        detail: str,
    ) -> Finding:
        return Finding(
            id=self._next_id(),
            title=title,
            resource=f"LambdaFunction {function_id}",
            path=path,
            severity=severity,
            rule=self.name,
            recommendation=f"{detail} {RISK_GUIDANCE}",
        )

    def _next_id(self) -> str:
        self._counter += 1
        return f"{FINDING_PREFIX}{self._counter:03d}"

    def _get_vpc_config(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        props = resource.get("Properties") or {}
        vpc_config = props.get("VpcConfig")
        if isinstance(vpc_config, dict):
            return vpc_config
        return None

    def _ensure_list(self, value: Any) -> List[str]:
        def _coerce(item: Any) -> Optional[str]:
            return self._normalize_reference(item)

        if value is None:
            return []
        if isinstance(value, list):
            coerced = [_coerce(item) for item in value]
            return [item for item in coerced if item]
        coerced_single = _coerce(value)
        return [coerced_single] if coerced_single else []

    def _normalize_reference(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            if "Ref" in value and isinstance(value["Ref"], str):
                return value["Ref"]
            if "Fn::GetAtt" in value and isinstance(value["Fn::GetAtt"], list):
                return ".".join(str(part) for part in value["Fn::GetAtt"])
        return None


def get_rule() -> Rule:
    return VpcEgressRule()
