"""sg-open.

The pattern fires on any ingress rule authorised with a source of 0.0.0.0/0 or
::/0. That includes a web server opening 443, which is not a finding. The
decision about *which* world-open rules are dangerous is made here, against a
sensitive-port list, and the revoke is surgical: only the world-open CIDRs on
the offending permission entries are removed, and every other rule and CIDR on
the group survives untouched.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from remediations.common import events as event_parser
from remediations.common.aws import AwsClients
from remediations.common.detection import Detection
from remediations.common.entrypoint import build
from remediations.common.models import DetectionEvent, Plan, Severity

WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"

#: Ports where world-open ingress is an incident rather than a design choice:
#: remote administration, databases, and datastores that historically ship
#: without authentication.
SENSITIVE_PORTS: frozenset[int] = frozenset(
    {
        20,
        21,
        22,
        23,
        25,
        135,
        137,
        138,
        139,
        389,
        445,
        512,
        513,
        514,
        1433,
        1521,
        2375,
        2376,
        2379,
        3000,
        3306,
        3389,
        4333,
        5432,
        5439,
        5500,
        5601,
        5900,
        5984,
        6379,
        7000,
        7001,
        8020,
        8086,
        8500,
        9042,
        9200,
        9300,
        11211,
        27017,
        27018,
        50070,
    }
)

#: Ports the internet is normally supposed to reach. Present for the reader:
#: a permission covering only these is left alone.
COMMONLY_PUBLIC_PORTS: frozenset[int] = frozenset({80, 443})


class SgOpen(Detection):
    id: ClassVar[str] = "sg-open"
    default_severity: ClassVar[Severity] = Severity.HIGH

    def plan(self, event: DetectionEvent, aws: AwsClients) -> Plan | None:
        group_id = str(event_parser.request_parameters(event).get("groupId") or "").strip()
        if not group_id:
            return None

        described = aws.ec2.describe_security_groups(GroupIds=[group_id])
        groups = described.get("SecurityGroups", [])
        if not groups:
            return None
        group = groups[0]

        permissions: Sequence[Mapping[str, Any]] = group.get("IpPermissions", []) or []
        revocations = [
            narrowed
            for permission in permissions
            if (narrowed := _world_open_dangerous_part(permission)) is not None
        ]
        if not revocations:
            return None

        tags = {
            str(tag["Key"]): str(tag.get("Value", ""))
            for tag in group.get("Tags", []) or []
            if isinstance(tag, Mapping) and "Key" in tag
        }

        covers_everything = any(rule.get("IpProtocol") == "-1" for rule in revocations)
        exposed = sorted({port for rule in revocations for port in _covered_sensitive_ports(rule)})
        reason = (
            f"security group {group_id} allows ingress from the internet on "
            f"{'all ports and protocols' if covers_everything else _describe_ports(exposed)}"
        )

        return Plan(
            resource_id=group_id,
            resource_arn=(
                f"arn:aws:ec2:{event.region}:{event.account_id}:security-group/{group_id}"
            ),
            reason=reason,
            severity=self.default_severity,
            snapshot={
                "group_id": group_id,
                "group_name": group.get("GroupName"),
                "vpc_id": group.get("VpcId"),
                "description": group.get("Description"),
                # The complete prior rule set, in the exact shape
                # AuthorizeSecurityGroupIngress accepts. Restoring is a copy of
                # this field back into the API.
                "ip_permissions_before": list(permissions),
                "ip_permissions_revoked": revocations,
                "tags": tags,
            },
            tags=tags,
            blast_radius={
                "attached_interfaces": _attached_interface_count(aws, group_id),
                "vpc_id": group.get("VpcId", "unknown"),
                "sensitive_ports": (
                    "all" if covers_everything else ",".join(str(port) for port in exposed)
                ),
            },
            intended_actions=tuple(
                f"revoke ingress {_render(rule)} from {group_id}" for rule in revocations
            ),
        )

    def apply(self, plan: Plan, aws: AwsClients) -> list[str]:
        revocations = plan.snapshot.get("ip_permissions_revoked", [])
        if not revocations:
            return []
        aws.ec2.revoke_security_group_ingress(
            GroupId=plan.resource_id, IpPermissions=list(revocations)
        )
        return [f"revoked ingress {_render(rule)} from {plan.resource_id}" for rule in revocations]


def _world_open_dangerous_part(
    permission: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return the minimal revocable subset of ``permission``, or ``None``.

    Only the world-open CIDRs are kept. A rule that allows both 10.0.0.0/8 and
    0.0.0.0/0 on port 22 loses the second and keeps the first — revoking the
    whole permission entry would take down legitimate internal access, which is
    precisely the DoS shape threat R2 warns about.
    """
    ipv4 = [
        entry
        for entry in permission.get("IpRanges", []) or []
        if isinstance(entry, Mapping) and entry.get("CidrIp") == WORLD_IPV4
    ]
    ipv6 = [
        entry
        for entry in permission.get("Ipv6Ranges", []) or []
        if isinstance(entry, Mapping) and entry.get("CidrIpv6") == WORLD_IPV6
    ]
    if not ipv4 and not ipv6:
        return None
    if not _covered_sensitive_ports(permission):
        return None

    narrowed: dict[str, Any] = {"IpProtocol": permission.get("IpProtocol", "-1")}
    if "FromPort" in permission:
        narrowed["FromPort"] = permission["FromPort"]
    if "ToPort" in permission:
        narrowed["ToPort"] = permission["ToPort"]
    if ipv4:
        narrowed["IpRanges"] = ipv4
    if ipv6:
        narrowed["Ipv6Ranges"] = ipv6
    return narrowed


def _covered_sensitive_ports(permission: Mapping[str, Any]) -> set[int]:
    """Which sensitive ports this permission entry reaches.

    ``IpProtocol: "-1"`` means every protocol and every port; it is treated as
    covering all of them rather than being enumerated.
    """
    protocol = str(permission.get("IpProtocol", "-1"))
    if protocol == "-1":
        return set(SENSITIVE_PORTS)
    if protocol not in {"tcp", "udp"}:
        return set()

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return set(SENSITIVE_PORTS)

    low, high = int(from_port), int(to_port)
    if low > high:
        low, high = high, low
    return {port for port in SENSITIVE_PORTS if low <= port <= high}


def _attached_interface_count(aws: AwsClients, group_id: str) -> int:
    """Best effort — blast radius is context for a human, not a control."""
    try:
        response = aws.ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [group_id]}]
        )
    except Exception:  # noqa: BLE001 - context is optional; the revoke is not
        return -1
    interfaces = response.get("NetworkInterfaces", [])
    return len(interfaces) if isinstance(interfaces, list) else -1


def _describe_ports(ports: Sequence[int]) -> str:
    if not ports:
        return "all ports"
    if len(ports) > 8:
        return f"{len(ports)} sensitive ports including {', '.join(str(p) for p in ports[:8])}"
    return ", ".join(str(port) for port in ports)


def _render(rule: Mapping[str, Any]) -> str:
    protocol = rule.get("IpProtocol", "-1")
    ports = "all" if protocol == "-1" else f"{rule.get('FromPort', '?')}-{rule.get('ToPort', '?')}"
    sources = [entry["CidrIp"] for entry in rule.get("IpRanges", []) if "CidrIp" in entry]
    sources += [entry["CidrIpv6"] for entry in rule.get("Ipv6Ranges", []) if "CidrIpv6" in entry]
    return f"{protocol}/{ports} from {','.join(sources)}"


lambda_handler = build(SgOpen())
