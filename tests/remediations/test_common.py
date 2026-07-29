"""Config, event parsing, redaction, and the circuit breaker in isolation."""

from __future__ import annotations

from typing import Any

import pytest

from remediations.common import redact
from remediations.common.circuit_breaker import CircuitBreaker
from remediations.common.config import Config, ConfigError
from remediations.common.events import UnsupportedEventError, as_items, parse
from tests.conftest import load_event

BASE_ENV = {"PAC_DETECTION_ID": "s3-public", "PAC_TABLE_NAME": "pac-audit"}


def test_dry_run_defaults_to_true() -> None:
    """A missing or malformed variable must never be the reason production
    resources start getting modified."""
    assert Config.from_env(BASE_ENV).dry_run is True


def test_dry_run_requires_an_explicit_opt_out() -> None:
    assert Config.from_env({**BASE_ENV, "PAC_DRY_RUN": "false"}).dry_run is False
    assert Config.from_env({**BASE_ENV, "PAC_DRY_RUN": ""}).dry_run is True


def test_malformed_boolean_fails_loudly() -> None:
    with pytest.raises(ConfigError):
        Config.from_env({**BASE_ENV, "PAC_DRY_RUN": "maybe"})


@pytest.mark.parametrize("missing", ["PAC_DETECTION_ID", "PAC_TABLE_NAME"])
def test_required_variables(missing: str) -> None:
    env = {key: value for key, value in BASE_ENV.items() if key != missing}
    with pytest.raises(ConfigError):
        Config.from_env(env)


def test_non_positive_window_is_rejected() -> None:
    with pytest.raises(ConfigError):
        Config.from_env({**BASE_ENV, "PAC_CIRCUIT_BREAKER_WINDOW_SECONDS": "0"})


def test_cloudtrail_event_parsing() -> None:
    event = parse(load_event("cloudtrail", "s3-public", "put-bucket-acl-public-read"))

    assert event.principal.arn == "arn:aws:iam::111111111111:user/lab-operator"
    assert event.principal.name == "lab-operator"
    assert event.source_ip == "203.0.113.42"
    assert event.region == "sa-east-1"
    assert not event.principal.is_root


def test_assumed_role_principal_name_comes_from_the_role_not_the_session() -> None:
    event = parse(load_event("cloudtrail", "s3-public", "put-bucket-policy-wildcard-principal"))

    assert event.principal.name == "lab-deploy"


def test_guardduty_event_parsing() -> None:
    event = parse(load_event("guardduty", "iam-key-leak", "unauthorized-access-root-credentials"))

    assert event.principal.is_root
    assert event.source_ip == "192.0.2.77"
    assert event.account_id == "111111111111"


def test_unknown_event_shape_is_rejected() -> None:
    with pytest.raises(UnsupportedEventError):
        parse({"source": "aws.lambda", "detail-type": "Something Else", "detail": {}})


def test_pac_automation_principal_is_recognised() -> None:
    event = parse(load_event("cloudtrail", "s3-public", "put-bucket-acl-public-read"))
    assert not event.principal.is_pac_automation()

    raw = load_event("cloudtrail", "s3-public", "put-bucket-acl-public-read")
    raw["detail"]["userIdentity"]["arn"] = (
        "arn:aws:sts::111111111111:assumed-role/pac-s3-public-remediation/x"
    )
    assert parse(raw).principal.is_pac_automation()


def test_as_items_flattens_both_cloudtrail_list_encodings() -> None:
    assert as_items({"items": [1, 2]}) == [1, 2]
    assert as_items([1, 2]) == [1, 2]
    assert as_items(None) == []


def test_redaction_drops_credential_valued_keys() -> None:
    scrubbed = redact.scrub(
        {
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "sessionToken": "FQoGZXIvYXdzEExample",
            "nested": {"Authorization": "Bearer abc123"},
        }
    )

    assert scrubbed["secretAccessKey"] == redact.PLACEHOLDER
    assert scrubbed["sessionToken"] == redact.PLACEHOLDER
    assert scrubbed["nested"]["Authorization"] == redact.PLACEHOLDER


def test_redaction_keeps_access_key_ids() -> None:
    """A key ID is an identifier, not a secret, and the iam-key-leak alert is
    useless without the key it is telling you to go look at."""
    scrubbed = redact.scrub({"accessKeyId": "AKIAIOSFODNN7EXAMPLE"})

    assert scrubbed["accessKeyId"] == "AKIAIOSFODNN7EXAMPLE"


def test_redaction_strips_slack_webhooks_from_free_text() -> None:
    text = "posting to https://hooks.slack.com/services/T000/B000/XXXXXXXX now"

    assert "hooks.slack.com" not in redact.scrub_text(text)


def test_redaction_truncates_runaway_strings() -> None:
    assert len(redact.scrub_text("a" * 10_000)) < 3_000


def test_breaker_opens_after_the_limit(aws: Any, audit_table: Any) -> None:
    breaker = CircuitBreaker(audit_table, "sg-open", limit=2, window_seconds=300)

    states = [breaker.check_and_increment(at=1_000) for _ in range(4)]

    assert [state.open for state in states] == [False, False, True, True]
    assert states[-1].count == 4


def test_breaker_resets_in_the_next_window(aws: Any, audit_table: Any) -> None:
    breaker = CircuitBreaker(audit_table, "sg-open", limit=1, window_seconds=300)

    assert not breaker.check_and_increment(at=1_000).open
    assert breaker.check_and_increment(at=1_100).open
    assert not breaker.check_and_increment(at=1_000 + 400).open


def test_breakers_are_independent_per_detection(aws: Any, audit_table: Any) -> None:
    """A storm on one detection must not blind the others."""
    noisy = CircuitBreaker(audit_table, "sg-open", limit=1, window_seconds=300)
    quiet = CircuitBreaker(audit_table, "s3-public", limit=1, window_seconds=300)

    noisy.check_and_increment(at=1_000)
    assert noisy.check_and_increment(at=1_000).open
    assert not quiet.check_and_increment(at=1_000).open
