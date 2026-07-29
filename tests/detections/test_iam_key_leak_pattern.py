"""`iam-key-leak` — what the EventBridge pattern does and does not deliver."""

from __future__ import annotations

import pytest

from tests.conftest import load_event, load_pattern
from tests.support.eventbridge import matches

PATTERN = load_pattern("iam-key-leak")


@pytest.mark.parametrize(
    "fixture",
    [
        "unauthorized-access-malicious-ip-caller",
        "unauthorized-access-root-credentials",
        "credential-exfiltration-assumed-role",
    ],
)
def test_pattern_matches_access_key_findings(fixture: str) -> None:
    assert matches(PATTERN, load_event("guardduty", "iam-key-leak", fixture))


def test_pattern_ignores_low_severity_findings() -> None:
    """Deactivating a production key because GuardDuty saw routine enumeration
    is threat R2: the remediation becomes the outage."""
    event = load_event("guardduty", "iam-key-leak", "benign-low-severity-recon")
    assert event["detail"]["severity"] == 2
    assert not matches(PATTERN, event)


def test_pattern_ignores_findings_about_other_resource_types() -> None:
    event = load_event("guardduty", "iam-key-leak", "benign-ec2-instance-finding")
    assert event["detail"]["severity"] == 8, "high severity, but not about a key"
    assert not matches(PATTERN, event)


@pytest.mark.parametrize("severity", [3.9, 3.0, 1.0])
def test_severity_floor_is_medium(severity: float) -> None:
    event = load_event("guardduty", "iam-key-leak", "unauthorized-access-malicious-ip-caller")
    event["detail"]["severity"] = severity
    assert not matches(PATTERN, event)


def test_pattern_ignores_finding_families_we_do_not_act_on() -> None:
    event = load_event("guardduty", "iam-key-leak", "unauthorized-access-malicious-ip-caller")
    event["detail"]["type"] = "Policy:IAMUser/RootCredentialUsage"
    assert not matches(PATTERN, event)
