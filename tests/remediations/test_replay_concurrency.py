"""Synthetic delivery interleavings; moto only, never a live AWS endpoint."""

from __future__ import annotations

import json
from typing import Any

import pytest
from botocore.exceptions import ClientError

from remediations.common.aws import AwsClients
from remediations.common.events import parse
from remediations.common.models import Status
from remediations.common.runtime import execute
from remediations.sg_open.handler import SgOpen
from tests.conftest import RecordingNotifier, load_event, make_config, seed_security_group


def setup_group(aws: AwsClients) -> tuple[str, dict[str, Any]]:
    group = seed_security_group(
        aws,
        permissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/8"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ],
    )
    raw = load_event("cloudtrail", "sg-open", "authorize-ingress-ssh-world")
    raw["detail"]["requestParameters"]["groupId"] = group
    return group, raw


def audit_items(table: Any) -> list[dict[str, Any]]:
    return [item for item in table.scan()["Items"] if item["pk"].startswith("AUDIT#")]


def test_repeated_dry_run_preserves_each_delivery_snapshot(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier
) -> None:
    group, raw = setup_group(aws)
    config = make_config(detection_id="sg-open", dry_run=True)
    execute(SgOpen(), raw, config, aws, notifier)
    aws.ec2.authorize_security_group_ingress(
        GroupId=group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    execute(SgOpen(), raw, config, aws, notifier)
    items = audit_items(audit_table)
    assert len(items) == 2, "a replay must not overwrite the original pre-change evidence"
    lengths = sorted(len(json.loads(item["snapshot"])["ip_permissions_before"]) for item in items)
    assert lengths == [2, 3]
    assert {item["status"] for item in items} == {"DRY_RUN"}


def test_two_inflight_plans_converge_without_false_failure(aws: AwsClients) -> None:
    from remediations.common.events import parse

    group, raw = setup_group(aws)
    detection = SgOpen()
    first = detection.plan(parse(raw), aws)
    second = detection.plan(parse(raw), aws)
    assert first is not None and second is not None
    detection.apply(first, aws)
    assert detection.apply(second, aws) == [], "the competing delivery already removed the target"
    remaining = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]
    ssh = next(rule for rule in remaining["IpPermissions"] if rule["FromPort"] == 22)
    assert ssh["IpRanges"] == [{"CidrIp": "10.0.0.0/8"}]
    assert {rule["FromPort"] for rule in remaining["IpPermissions"]} == {22, 443}


def test_competitor_removes_target_between_read_and_revoke(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    group, raw = setup_group(aws)
    revoke = aws.ec2.revoke_security_group_ingress

    def competing_revoke(**kwargs: Any) -> Any:
        revoke(**kwargs)  # The competing invocation wins after our pre-apply read.
        return revoke(**kwargs)  # Real moto EC2 raises InvalidPermission.NotFound.

    monkeypatch.setattr(aws.ec2, "revoke_security_group_ingress", competing_revoke)
    outcome = execute(SgOpen(), raw, make_config(detection_id="sg-open"), aws, notifier)
    assert outcome.status is Status.APPLIED
    assert outcome.actions == (), "do not attribute a competitor's mutation to this delivery"
    assert audit_items(audit_table)[0]["status"] == "APPLIED"
    remaining = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]
    ssh = next(rule for rule in remaining["IpPermissions"] if rule["FromPort"] == 22)
    assert ssh["IpRanges"] == [{"CidrIp": "10.0.0.0/8"}]


def test_success_response_without_effect_is_not_applied(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, raw = setup_group(aws)
    monkeypatch.setattr(aws.ec2, "revoke_security_group_ingress", lambda **kwargs: {"Return": True})
    outcome = execute(SgOpen(), raw, make_config(detection_id="sg-open"), aws, notifier)
    assert outcome.status is Status.FAILED
    assert "remain" in str(outcome.error)
    assert audit_items(audit_table)[0]["status"] == "FAILED"
    assert notifier.statuses == ["FAILED"]


@pytest.mark.parametrize(
    "code", ["InvalidPermission.NotFound", "UnauthorizedOperation", "RequestLimitExceeded"]
)
def test_revoke_error_with_target_remaining_is_failed(
    aws: AwsClients,
    audit_table: Any,
    notifier: RecordingNotifier,
    monkeypatch: pytest.MonkeyPatch,
    code: str,
) -> None:
    _, raw = setup_group(aws)

    def failed_revoke(**kwargs: Any) -> Any:
        raise ClientError(
            {"Error": {"Code": code, "Message": "injected"}}, "RevokeSecurityGroupIngress"
        )

    monkeypatch.setattr(aws.ec2, "revoke_security_group_ingress", failed_revoke)
    outcome = execute(SgOpen(), raw, make_config(detection_id="sg-open"), aws, notifier)
    assert outcome.status is Status.FAILED
    assert code in str(outcome.error)
    assert audit_items(audit_table)[0]["status"] == "FAILED"


def test_apply_never_widens_snapshot_to_new_dangerous_sources(aws: AwsClients) -> None:
    group, raw = setup_group(aws)
    detection = SgOpen()
    plan = detection.plan(parse(raw), aws)
    assert plan is not None
    aws.ec2.authorize_security_group_ingress(
        GroupId=group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )
    detection.apply(plan, aws)
    remaining = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]
    ssh = next(rule for rule in remaining["IpPermissions"] if rule["FromPort"] == 22)
    assert ssh["IpRanges"] == [{"CidrIp": "10.0.0.0/8"}]
    assert ssh["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}], "a new finding needs its own snapshot"


def test_delayed_replay_after_remediation_is_skipped_without_changing_resource(
    aws: AwsClients,
    audit_table: Any,
    notifier: RecordingNotifier,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group, raw = setup_group(aws)
    config = make_config(detection_id="sg-open")
    first = execute(SgOpen(), raw, config, aws, notifier)
    before = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"]

    def unexpected_mutation(**kwargs: Any) -> Any:
        pytest.fail("a delayed event must not mutate an already-corrected resource")

    monkeypatch.setattr(aws.ec2, "revoke_security_group_ingress", unexpected_mutation)
    raw["detail"]["eventTime"] = "2020-01-01T00:00:00Z"
    second = execute(SgOpen(), raw, config, aws, notifier)
    assert first.status is Status.APPLIED
    assert second.status is Status.SKIPPED
    assert aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"] == before
    assert sorted(item["status"] for item in audit_items(audit_table)) == ["APPLIED", "SKIPPED"]


def test_interleaved_deliveries_keep_separate_audit_outcomes(
    aws: AwsClients,
    audit_table: Any,
    notifier: RecordingNotifier,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, raw = setup_group(aws)
    config = make_config(detection_id="sg-open")
    first = SgOpen()
    original_apply = first.apply

    def interleaved_apply(plan: Any, clients: AwsClients) -> list[str]:
        competitor = execute(SgOpen(), raw, config, clients, notifier)
        assert competitor.status is Status.APPLIED
        assert competitor.actions
        return original_apply(plan, clients)

    monkeypatch.setattr(first, "apply", interleaved_apply)
    outcome = execute(first, raw, config, aws, notifier)
    assert outcome.status is Status.APPLIED
    assert outcome.actions == ()
    items = audit_items(audit_table)
    assert len(items) == 2
    assert {item["status"] for item in items} == {"APPLIED"}
    assert sorted(len(item["actions"]) for item in items) == [0, 1]
    assert all(json.loads(item["snapshot"])["ip_permissions_revoked"] for item in items)


def test_snapshot_write_failure_prevents_ec2_mutation(
    aws: AwsClients,
    audit_table: Any,
    notifier: RecordingNotifier,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from remediations.common.audit import AuditLog

    group, raw = setup_group(aws)
    before = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"]

    def unavailable_snapshot(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("snapshot unavailable")

    def unexpected_mutation(**kwargs: Any) -> Any:
        pytest.fail("must persist snapshot before mutation")

    monkeypatch.setattr(AuditLog, "open", unavailable_snapshot)
    monkeypatch.setattr(aws.ec2, "revoke_security_group_ingress", unexpected_mutation)
    with pytest.raises(RuntimeError, match="snapshot unavailable"):
        execute(SgOpen(), raw, make_config(detection_id="sg-open"), aws, notifier)
    assert aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"] == before
    assert audit_items(audit_table) == []
    assert notifier.sent == []


def test_close_failure_keeps_planned_evidence_and_replay_does_not_reopen_access(
    aws: AwsClients,
    audit_table: Any,
    notifier: RecordingNotifier,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from remediations.common.audit import AuditLog

    group, raw = setup_group(aws)
    config = make_config(detection_id="sg-open")

    def failed_close(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("audit close unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(AuditLog, "close", failed_close)
        with pytest.raises(RuntimeError, match="audit close unavailable"):
            execute(SgOpen(), raw, config, aws, notifier)
    original = audit_items(audit_table)[0]
    assert original["status"] == "PLANNED"
    assert json.loads(original["snapshot"])["ip_permissions_revoked"]
    assert notifier.sent == [], "no success alert when audit close failed"
    remaining = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]
    ssh = next(rule for rule in remaining["IpPermissions"] if rule["FromPort"] == 22)
    assert ssh["IpRanges"] == [{"CidrIp": "10.0.0.0/8"}]
    assert execute(SgOpen(), raw, config, aws, notifier).status is Status.SKIPPED
    items = audit_items(audit_table)
    assert len(items) == 2
    assert original in items, "replay must not erase unresolved evidence"
    assert sorted(item["status"] for item in items) == ["PLANNED", "SKIPPED"]
