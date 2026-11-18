"""Regression tests for the independent review findings."""

from unittest.mock import Mock

import pytest

from canary.handler import lambda_handler
from canary.observer import evaluate
from tests.canary.test_heartbeat import evidence, ledger


@pytest.mark.parametrize(
    "event",
    [
        {"time": "1970-01-01T00:00:00Z", "source": "aws.events", "detail-type": "Scheduled Event"},
        {"time": "2999-01-01T00:00:00Z", "source": "aws.events", "detail-type": "Scheduled Event"},
        {},
    ],
)
def test_old_future_or_missing_schedule_cannot_mutate(event: dict, monkeypatch: pytest.MonkeyPatch):
    aws = Mock(side_effect=AssertionError("stale event must not resolve clients"))
    monkeypatch.setattr("canary.handler.AwsClients", aws)
    with pytest.raises(ValueError, match="schedule"):
        lambda_handler(event)
    aws.assert_not_called()


def test_success_does_not_erase_unresolved_delivery() -> None:
    unresolved = evidence() | {"status": "PLANNED"}
    assert not evaluate(
        ledger(),
        [unresolved, evidence()],
        slot=600,
        group_id="sg-1",
        account_id="123456789012",
        region="sa-east-1",
        safe=True,
    )


def test_arbitrary_action_is_not_verified_revoke() -> None:
    assert not evaluate(
        ledger(),
        [evidence() | {"actions": ["not a revoke"]}],
        slot=600,
        group_id="sg-1",
        account_id="123456789012",
        region="sa-east-1",
        safe=True,
    )
