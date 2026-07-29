"""The pipeline invariants, tested with a stub detection.

These are the properties the threat model depends on. They are enforced in
`remediations.common.runtime` rather than in each handler, so they are tested
once, here, against a detection that does nothing but record that it was called.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from remediations.common.aws import AwsClients
from remediations.common.detection import Detection
from remediations.common.models import DetectionEvent, Plan, Severity, Status
from remediations.common.runtime import execute
from tests.conftest import RecordingNotifier, load_event, make_config

RESOURCE = "pac-lab-demo-assets"


class StubDetection(Detection):
    id: ClassVar[str] = "stub"

    def __init__(
        self,
        *,
        plan_result: Plan | None = None,
        raises: Exception | None = None,
        tags: dict[str, str] | None = None,
        intended: tuple[str, ...] = ("do the thing",),
    ) -> None:
        self._plan_result = plan_result
        self._raises = raises
        self._tags = tags or {}
        self._intended = intended
        self.applied = 0

    def plan(self, event: DetectionEvent, aws: AwsClients) -> Plan | None:
        if self._plan_result is not None:
            return self._plan_result
        return Plan(
            resource_id=RESOURCE,
            resource_arn=f"arn:aws:s3:::{RESOURCE}",
            reason="stub finding",
            severity=Severity.HIGH,
            snapshot={"before": "original-state"},
            tags=self._tags,
            blast_radius={"scope": "test"},
            intended_actions=self._intended,
        )

    def apply(self, plan: Plan, aws: AwsClients) -> list[str]:
        self.applied += 1
        if self._raises is not None:
            raise self._raises
        return ["did the thing"]


@pytest.fixture
def raw_event() -> dict[str, Any]:
    return load_event("cloudtrail", "s3-public", "put-bucket-acl-public-read")


def _items(table: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = table.scan()["Items"]
    return result


def _audit_items(table: Any) -> list[dict[str, Any]]:
    return [item for item in _items(table) if str(item["pk"]).startswith("AUDIT#")]


def test_applies_and_records(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    detection = StubDetection()

    outcome = execute(detection, raw_event, make_config(), aws, notifier)

    assert outcome.status is Status.APPLIED
    assert detection.applied == 1
    assert notifier.statuses == ["APPLIED"]

    item = _audit_items(audit_table)[0]
    assert item["status"] == "APPLIED"
    assert json.loads(item["snapshot"])["before"] == "original-state"
    assert item["actions"] == ["did the thing"]


def test_snapshot_survives_a_failed_remediation(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    """The point of writing the snapshot before applying: when the remediation
    blows up, incident response still has the original resource state."""
    detection = StubDetection(raises=RuntimeError("throttled"))

    outcome = execute(detection, raw_event, make_config(), aws, notifier)

    assert outcome.status is Status.FAILED
    assert outcome.error is not None
    assert "throttled" in outcome.error

    item = _audit_items(audit_table)[0]
    assert json.loads(item["snapshot"])["before"] == "original-state"
    assert notifier.statuses == ["FAILED"]


def test_dry_run_changes_nothing_but_still_records_and_alerts(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    detection = StubDetection()

    outcome = execute(detection, raw_event, make_config(dry_run=True), aws, notifier)

    assert outcome.status is Status.DRY_RUN
    assert detection.applied == 0
    assert outcome.actions == ("do the thing",)
    assert _audit_items(audit_table)[0]["status"] == "DRY_RUN"
    assert notifier.statuses == ["DRY_RUN"]


def test_exclusion_tag_prevents_action_and_still_alerts(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    """Someone deliberately excluded this resource. That is a decision, not a
    silence — an excluded bucket going public is still worth knowing about."""
    detection = StubDetection(tags={"pac:exclude": "owned by data-eng, ticket SEC-41"})

    outcome = execute(detection, raw_event, make_config(), aws, notifier)

    assert outcome.status is Status.SKIPPED
    assert detection.applied == 0
    assert "SEC-41" in outcome.reason
    assert notifier.statuses == ["SKIPPED"]


def test_benign_plan_is_a_no_op(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    class Benign(StubDetection):
        def plan(self, event: DetectionEvent, aws: AwsClients) -> Plan | None:
            return None

    outcome = execute(Benign(), raw_event, make_config(), aws, notifier)

    assert outcome.status is Status.SKIPPED
    assert outcome.severity is Severity.INFO
    assert notifier.sent == [], "a benign event must not page anyone"


def test_self_triggered_events_are_dropped(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    """Our own remediation calls are CloudTrail events that match our own
    patterns. Without this check the function invokes itself forever."""
    raw_event["detail"]["userIdentity"] = {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::111111111111:assumed-role/pac-s3-public-remediation/pac",
        "accountId": "111111111111",
        "sessionContext": {"sessionIssuer": {"userName": "pac-s3-public-remediation"}},
    }
    detection = StubDetection()

    outcome = execute(detection, raw_event, make_config(), aws, notifier)

    assert outcome.status is Status.SKIPPED
    assert detection.applied == 0
    assert notifier.sent == []


def test_empty_intended_actions_escalates_without_acting(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    detection = StubDetection(intended=())

    outcome = execute(detection, raw_event, make_config(), aws, notifier)

    assert outcome.status is Status.ESCALATED
    assert detection.applied == 0
    assert _audit_items(audit_table)[0]["status"] == "ESCALATED"
    assert notifier.statuses == ["ESCALATED"]


def test_circuit_breaker_stops_a_remediation_storm(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    """Threat R2: an attacker who can trigger the detection at will turns
    auto-remediation into a denial of service. After the limit, we stop and
    shout instead of continuing."""
    detection = StubDetection()
    config = make_config(circuit_breaker_max_actions=3)

    statuses = []
    for index in range(6):
        raw_event["detail"]["eventID"] = f"event-{index}"
        statuses.append(execute(detection, raw_event, config, aws, notifier).status)

    assert statuses == [
        Status.APPLIED,
        Status.APPLIED,
        Status.APPLIED,
        Status.BLOCKED,
        Status.BLOCKED,
        Status.BLOCKED,
    ]
    assert detection.applied == 3
    assert notifier.sent[-1][1].severity is Severity.CRITICAL


def test_breaker_counts_dry_runs_too(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    """A dry-run deployment that would have tripped the breaker is exactly the
    signal you want before enabling remediation."""
    detection = StubDetection()
    config = make_config(dry_run=True, circuit_breaker_max_actions=2)

    statuses = []
    for index in range(3):
        raw_event["detail"]["eventID"] = f"event-{index}"
        statuses.append(execute(detection, raw_event, config, aws, notifier).status)

    assert statuses == [Status.DRY_RUN, Status.DRY_RUN, Status.BLOCKED]


def test_audit_record_carries_the_investigative_context(
    aws: AwsClients, audit_table: Any, notifier: RecordingNotifier, raw_event: dict[str, Any]
) -> None:
    execute(StubDetection(), raw_event, make_config(), aws, notifier)

    item = _audit_items(audit_table)[0]
    assert item["principal_arn"] == "arn:aws:iam::111111111111:user/lab-operator"
    assert item["source_ip"] == "203.0.113.42"
    assert item["account_id"] == "111111111111"
    assert item["region"] == "sa-east-1"
    assert item["event_id"] == "8c2c8e6a-3b2f-4a1e-9d7c-1f2e3d4c5b6a"
