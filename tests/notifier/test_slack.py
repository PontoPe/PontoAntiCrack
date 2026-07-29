"""Alert content and deduplication."""

from __future__ import annotations

import json
from typing import Any

import pytest

from notifier.dedup import Deduplicator, fingerprint
from notifier.slack import SlackNotifier, build_payload
from remediations.common.aws import AwsClients
from remediations.common.events import parse
from remediations.common.models import Outcome, Plan, Severity, Status
from tests.conftest import load_event

WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"


@pytest.fixture
def event() -> Any:
    return parse(load_event("cloudtrail", "s3-public", "put-bucket-acl-public-read"))


@pytest.fixture
def plan() -> Plan:
    return Plan(
        resource_id="pac-lab-demo-assets",
        resource_arn="arn:aws:s3:::pac-lab-demo-assets",
        reason="ACL grants AllUsers:READ",
        severity=Severity.HIGH,
        snapshot={"acl": {"Grants": []}},
        blast_radius={"public_via": "acl", "region": "sa-east-1"},
        intended_actions=("enable all four Block Public Access settings",),
    )


def _outcome(status: Status = Status.APPLIED, **overrides: Any) -> Outcome:
    base: dict[str, Any] = {
        "detection_id": "s3-public",
        "status": status,
        "severity": Severity.HIGH,
        "resource_id": "pac-lab-demo-assets",
        "reason": "ACL grants AllUsers:READ",
        "actions": ("enabled Block Public Access on s3://pac-lab-demo-assets",),
    }
    base.update(overrides)
    return Outcome(**base)


def _text(payload: dict[str, Any]) -> str:
    return json.dumps(payload)


def test_alert_carries_the_context_needed_to_act(event: Any, plan: Plan) -> None:
    payload = build_payload(event, _outcome(), plan, "lab")
    body = _text(payload)

    assert "s3-public" in body
    assert "pac-lab-demo-assets" in body
    assert "arn:aws:iam::111111111111:user/lab-operator" in body
    assert "203.0.113.42" in body
    assert "public_via=acl" in body
    assert "lab" in payload["text"]


def test_alert_says_what_was_done(event: Any, plan: Plan) -> None:
    payload = build_payload(event, _outcome(), plan, "lab")

    assert "Actions taken" in _text(payload)
    assert "remediated" in payload["text"]


def test_dry_run_alert_says_actions_were_withheld(event: Any, plan: Plan) -> None:
    outcome = _outcome(Status.DRY_RUN, actions=("enable Block Public Access",))
    payload = build_payload(event, outcome, plan, "dev")

    assert "Actions withheld" in _text(payload)
    assert "dry run" in payload["text"]


def test_escalated_alert_is_unmistakable(event: Any, plan: Plan) -> None:
    outcome = _outcome(Status.ESCALATED, severity=Severity.CRITICAL, actions=())
    payload = build_payload(event, outcome, plan, "prod")

    assert "MANUAL ACTION REQUIRED" in payload["text"]


def test_alert_never_carries_credential_material(event: Any, plan: Plan) -> None:
    """Threat R5. The alert is an outbound message to a third party; a secret in
    it is a secret in someone else's log retention."""
    leaky = Plan(
        resource_id=plan.resource_id,
        resource_arn=plan.resource_arn,
        reason=f"exfiltration to {WEBHOOK}",
        severity=Severity.HIGH,
        snapshot={},
        blast_radius={"secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        intended_actions=plan.intended_actions,
    )
    payload = build_payload(event, _outcome(reason=leaky.reason), leaky, "lab")
    body = _text(payload)

    assert "hooks.slack.com" not in body
    assert "wJalrXUtnFEMI" not in body


def test_error_is_surfaced(event: Any, plan: Plan) -> None:
    outcome = _outcome(Status.FAILED, error="ClientError: RequestLimitExceeded")
    payload = build_payload(event, outcome, plan, "lab")

    assert "RequestLimitExceeded" in _text(payload)


def test_alert_states_that_the_snapshot_was_taken(event: Any, plan: Plan) -> None:
    payload = build_payload(event, _outcome(), plan, "lab")

    assert "snapshotted" in _text(payload)


def test_deduplication_suppresses_the_second_identical_alert(audit_table: Any) -> None:
    dedup = Deduplicator(audit_table, window_seconds=900)
    key = fingerprint("sg-open", "sg-0abc", "APPLIED", "high")

    assert dedup.claim(key, at=1_000) is True
    assert dedup.claim(key, at=1_100) is False


def test_deduplication_window_expires(audit_table: Any) -> None:
    """The window is enforced by the conditional write, not by the DynamoDB TTL —
    TTL deletion can lag by up to 48 hours, which would suppress alerts for the
    rest of the day."""
    dedup = Deduplicator(audit_table, window_seconds=900)
    key = fingerprint("sg-open", "sg-0abc", "APPLIED", "high")

    assert dedup.claim(key, at=1_000) is True
    assert dedup.claim(key, at=1_000 + 901) is True


def test_a_different_outcome_for_the_same_resource_is_not_suppressed(audit_table: Any) -> None:
    """A resource that was skipped and is later actually remediated is a
    different thing to know about."""
    dedup = Deduplicator(audit_table, window_seconds=900)

    assert dedup.claim(fingerprint("sg-open", "sg-0abc", "DRY_RUN", "high"), at=1_000)
    assert dedup.claim(fingerprint("sg-open", "sg-0abc", "APPLIED", "high"), at=1_000)


def test_notifier_posts_once_and_suppresses_the_repeat(
    aws: AwsClients, audit_table: Any, event: Any, plan: Plan, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = aws.secretsmanager.create_secret(
        Name="pac/slack-webhook", SecretString=json.dumps({"webhook_url": WEBHOOK})
    )
    posted: list[dict[str, Any]] = []

    def fake_post(self: SlackNotifier, payload: dict[str, Any]) -> None:
        posted.append(payload)

    monkeypatch.setattr(SlackNotifier, "_post", fake_post)

    notifier = SlackNotifier(
        secret_arn=secret["ARN"],
        aws=aws,
        table=audit_table,
        environment="lab",
        dedup_window_seconds=900,
    )

    assert notifier.notify(event, _outcome(), plan) is True
    assert notifier.notify(event, _outcome(), plan) is False
    assert len(posted) == 1


def test_webhook_is_read_from_secrets_manager_not_the_environment(
    aws: AwsClients, audit_table: Any
) -> None:
    """Threat R5: an env var shows up in GetFunctionConfiguration, in CloudTrail,
    and in `terraform show`. A secret ARN does not."""
    secret = aws.secretsmanager.create_secret(Name="pac/slack-webhook", SecretString=WEBHOOK)
    notifier = SlackNotifier(
        secret_arn=secret["ARN"],
        aws=aws,
        table=audit_table,
        environment="lab",
        dedup_window_seconds=900,
    )

    assert notifier._resolve_webhook() == WEBHOOK


def test_json_wrapped_secret_is_unwrapped(aws: AwsClients, audit_table: Any) -> None:
    secret = aws.secretsmanager.create_secret(
        Name="pac/slack-webhook", SecretString=json.dumps({"webhook_url": WEBHOOK})
    )
    notifier = SlackNotifier(
        secret_arn=secret["ARN"],
        aws=aws,
        table=audit_table,
        environment="lab",
        dedup_window_seconds=900,
    )

    assert notifier._resolve_webhook() == WEBHOOK
