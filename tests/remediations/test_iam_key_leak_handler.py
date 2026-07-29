"""`iam-key-leak` handler: deactivate, never delete, never touch root."""

from __future__ import annotations

from typing import Any

from remediations.common import events as event_parser
from remediations.common.aws import AwsClients
from remediations.iam_key_leak.handler import IamKeyLeak
from tests.conftest import load_event, seed_iam_user

DETECTION = IamKeyLeak()
USER = "lab-ci-publisher"


def _event(fixture: str, access_key_id: str | None = None) -> Any:
    raw = load_event("guardduty", "iam-key-leak", fixture)
    if access_key_id is not None:
        raw["detail"]["resource"]["accessKeyDetails"]["accessKeyId"] = access_key_id
    return event_parser.parse(raw)


def _status(aws: AwsClients, user: str, key_id: str) -> str:
    for entry in aws.iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
        if entry["AccessKeyId"] == key_id:
            return str(entry["Status"])
    raise AssertionError(f"{key_id} no longer exists")


def test_active_user_key_produces_a_plan(aws: AwsClients) -> None:
    key_id = seed_iam_user(aws, USER, tags={"owner": "platform"})

    plan = DETECTION.plan(_event("unauthorized-access-malicious-ip-caller", key_id), aws)

    assert plan is not None
    assert plan.resource_id == key_id
    assert plan.intended_actions == (f"set access key {key_id} of user {USER} to Inactive",)
    assert plan.tags == {"owner": "platform"}


def test_apply_deactivates_and_does_not_delete(aws: AwsClients) -> None:
    """Deleting the key would take GetAccessKeyLastUsed with it, and that record
    is often the only evidence of what the attacker actually reached."""
    key_id = seed_iam_user(aws, USER)
    plan = DETECTION.plan(_event("unauthorized-access-malicious-ip-caller", key_id), aws)
    assert plan is not None

    actions = DETECTION.apply(plan, aws)

    assert _status(aws, USER, key_id) == "Inactive"
    assert any("not deleted" in action for action in actions)


def test_snapshot_captures_last_used_before_deactivation(aws: AwsClients) -> None:
    key_id = seed_iam_user(aws, USER)

    plan = DETECTION.plan(_event("unauthorized-access-malicious-ip-caller", key_id), aws)

    assert plan is not None
    assert "access_key_last_used" in plan.snapshot
    assert plan.snapshot["access_key_metadata"]["Status"] == "Active"
    assert plan.snapshot["guardduty_finding"]["severity"] == 5


def test_already_inactive_key_produces_no_plan(aws: AwsClients) -> None:
    """Re-deactivating would write a misleading APPLIED record."""
    key_id = seed_iam_user(aws, USER)
    aws.iam.update_access_key(UserName=USER, AccessKeyId=key_id, Status="Inactive")

    assert DETECTION.plan(_event("unauthorized-access-malicious-ip-caller", key_id), aws) is None


def test_root_credentials_are_escalated_never_acted_on(aws: AwsClients) -> None:
    """An automation role that can disable root is a bigger problem than the
    finding. An empty intended-action list is how the handler says
    'alert a human and change nothing'."""
    plan = DETECTION.plan(_event("unauthorized-access-root-credentials"), aws)

    assert plan is not None
    assert plan.intended_actions == ()
    assert plan.severity.value == "critical"
    assert "root" in plan.reason.lower()
    assert plan.resource_arn.endswith(":root")


def test_assumed_role_session_is_escalated(aws: AwsClients) -> None:
    """GuardDuty reports resourceType AccessKey even for temporary credentials.
    UpdateAccessKey cannot act on those, and pretending otherwise would produce
    a confident APPLIED for a remediation that never happened."""
    plan = DETECTION.plan(_event("credential-exfiltration-assumed-role"), aws)

    assert plan is not None
    assert plan.intended_actions == ()
    assert "temporary" in plan.reason.lower()
    assert ":role/" in plan.resource_arn


def test_finding_without_an_access_key_produces_no_plan(aws: AwsClients) -> None:
    raw = load_event("guardduty", "iam-key-leak", "unauthorized-access-malicious-ip-caller")
    raw["detail"]["resource"]["accessKeyDetails"] = {}

    assert DETECTION.plan(event_parser.parse(raw), aws) is None


def test_source_ip_comes_from_the_guardduty_action(aws: AwsClients) -> None:
    key_id = seed_iam_user(aws, USER)
    event = _event("unauthorized-access-malicious-ip-caller", key_id)

    assert event.source_ip == "198.51.100.253"

    plan = DETECTION.plan(event, aws)
    assert plan is not None
    assert "198.51.100.253" in plan.reason
