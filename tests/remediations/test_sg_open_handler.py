"""`sg-open` handler: which world-open rules get revoked, and which survive."""

from __future__ import annotations

from typing import Any

from remediations.common import events as event_parser
from remediations.common.aws import AwsClients
from remediations.sg_open.handler import SgOpen
from tests.conftest import load_event, seed_security_group

DETECTION = SgOpen()

WORLD_V4 = [{"CidrIp": "0.0.0.0/0"}]
INTERNAL_V4 = [{"CidrIp": "10.0.0.0/8"}]


def _event(group_id: str, fixture: str = "authorize-ingress-ssh-world") -> Any:
    raw = load_event("cloudtrail", "sg-open", fixture)
    raw["detail"]["requestParameters"]["groupId"] = group_id
    return event_parser.parse(raw)


def _ssh_world() -> dict[str, Any]:
    return {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": list(WORLD_V4)}


def _ingress(aws: AwsClients, group_id: str) -> list[dict[str, Any]]:
    groups = aws.ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    result: list[dict[str, Any]] = groups[0]["IpPermissions"]
    return result


def test_ssh_open_to_the_world_produces_a_plan(aws: AwsClients) -> None:
    group_id = seed_security_group(aws, permissions=[_ssh_world()])

    plan = DETECTION.plan(_event(group_id), aws)

    assert plan is not None
    assert plan.resource_id == group_id
    assert "22" in plan.reason


def test_https_open_to_the_world_produces_no_plan(aws: AwsClients) -> None:
    """The pattern delivers this event because EventBridge cannot evaluate a
    port range. A public web server is not an incident, and the handler is where
    that gets decided."""
    permissions = [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": list(WORLD_V4)}
    ]
    group_id = seed_security_group(aws, permissions=permissions)

    assert DETECTION.plan(_event(group_id, "authorize-ingress-https-world"), aws) is None


def test_internal_ssh_produces_no_plan(aws: AwsClients) -> None:
    permissions = [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": list(INTERNAL_V4)}
    ]
    group_id = seed_security_group(aws, permissions=permissions)

    assert DETECTION.plan(_event(group_id), aws) is None


def test_all_protocols_open_to_the_world_produces_a_plan(aws: AwsClients) -> None:
    permissions = [{"IpProtocol": "-1", "IpRanges": list(WORLD_V4)}]
    group_id = seed_security_group(aws, permissions=permissions)

    plan = DETECTION.plan(_event(group_id), aws)

    assert plan is not None
    assert "all ports" in plan.reason


def test_wide_port_range_covering_ssh_produces_a_plan(aws: AwsClients) -> None:
    permissions = [
        {"IpProtocol": "tcp", "FromPort": 1, "ToPort": 65535, "IpRanges": list(WORLD_V4)}
    ]
    group_id = seed_security_group(aws, permissions=permissions)

    plan = DETECTION.plan(_event(group_id), aws)

    assert plan is not None


def test_apply_revokes_only_the_world_cidr(aws: AwsClients) -> None:
    """The rule allows both the bastion subnet and the internet on port 22.
    Revoking the whole entry would cut off legitimate access — an outage caused
    by our own remediation, which is threat R2."""
    permissions = [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}, {"CidrIp": "0.0.0.0/0"}],
        }
    ]
    group_id = seed_security_group(aws, permissions=permissions)
    plan = DETECTION.plan(_event(group_id), aws)
    assert plan is not None

    DETECTION.apply(plan, aws)

    remaining = _ingress(aws, group_id)
    cidrs = {entry["CidrIp"] for rule in remaining for entry in rule.get("IpRanges", [])}
    assert cidrs == {"10.0.0.0/8"}


def test_apply_leaves_unrelated_rules_alone(aws: AwsClients) -> None:
    permissions = [
        _ssh_world(),
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": list(WORLD_V4)},
    ]
    group_id = seed_security_group(aws, permissions=permissions)
    plan = DETECTION.plan(_event(group_id), aws)
    assert plan is not None

    DETECTION.apply(plan, aws)

    remaining = _ingress(aws, group_id)
    ports = {rule.get("FromPort") for rule in remaining}
    assert ports == {443}


def test_snapshot_holds_the_restorable_rule_set(aws: AwsClients) -> None:
    group_id = seed_security_group(aws, permissions=[_ssh_world()], tags={"env": "lab"})

    plan = DETECTION.plan(_event(group_id), aws)

    assert plan is not None
    before = plan.snapshot["ip_permissions_before"]
    assert before, "the full prior rule set must be recoverable from the audit record"
    assert before[0]["FromPort"] == 22
    assert plan.tags == {"env": "lab"}
    # Exactly the shape authorize-security-group-ingress takes back.
    revoked = plan.snapshot["ip_permissions_revoked"]
    assert revoked[0]["IpRanges"] == WORLD_V4


def test_ipv6_world_open_is_revoked(aws: AwsClients) -> None:
    permissions = [
        {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
    ]
    group_id = seed_security_group(aws, permissions=permissions)
    plan = DETECTION.plan(_event(group_id, "authorize-ingress-rdp-world-ipv6"), aws)
    assert plan is not None

    DETECTION.apply(plan, aws)

    assert not _ingress(aws, group_id)


def test_udp_dns_to_the_world_is_left_alone(aws: AwsClients) -> None:
    """Port 53 is not on the sensitive list. A public resolver is a design
    choice, not a finding."""
    permissions = [{"IpProtocol": "udp", "FromPort": 53, "ToPort": 53, "IpRanges": list(WORLD_V4)}]
    group_id = seed_security_group(aws, permissions=permissions)

    assert DETECTION.plan(_event(group_id), aws) is None


def test_missing_group_produces_no_plan(aws: AwsClients) -> None:
    raw = load_event("cloudtrail", "sg-open", "authorize-ingress-ssh-world")
    raw["detail"]["requestParameters"] = {}

    assert DETECTION.plan(event_parser.parse(raw), aws) is None
