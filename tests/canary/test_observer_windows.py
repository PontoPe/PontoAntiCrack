"""Scheduled observation excludes the next probe's normal propagation window."""

from unittest.mock import Mock

import pytest

from canary.handler import schedule_time
from canary.observer import evaluate, observe
from tests.canary.test_heartbeat import evidence, ledger


def test_unrelated_revoke_is_not_canary_effect() -> None:
    assert not evaluate(
        ledger(),
        [evidence() | {"actions": ["revoked ingress udp/3389-3389 from 0.0.0.0/0 from sg-1"]}],
        slot=600,
        group_id="sg-1",
        account_id="123456789012",
        region="sa-east-1",
        safe=True,
    )


def test_observe_current_slot_before_next_probe() -> None:
    scope, aws, table = Mock(), Mock(), Mock()
    scope.round_id = "round"
    scope.group_id = "sg-1"
    scope.account_id = "123456789012"
    scope.region = "sa-east-1"
    scope.inspect.return_value = {"IpPermissions": []}
    table.get_item.return_value = {"Item": ledger()}
    table.query.return_value = {"Items": [evidence()]}
    assert observe(scope, aws, table, now=840)
    assert table.get_item.call_args.kwargs["Key"]["sk"] == "000000000600"


@pytest.mark.parametrize("now", [600, 839, 900])
def test_observer_refuses_outside_nonoverlapping_window(now: int) -> None:
    with pytest.raises(ValueError, match="observation window"):
        observe(Mock(), Mock(), Mock(), now=now)


def test_scheduled_time_does_not_move_on_retry_across_boundary() -> None:
    event = {
        "time": "1970-01-01T00:14:59Z",
        "source": "aws.events",
        "detail-type": "Scheduled Event",
    }
    assert schedule_time(event, now=901) == 899


@pytest.mark.parametrize("completed", ["garbage", "1970-01-01T00:15:00Z", "1970-01-01T00:10:02"])
def test_invalid_or_next_slot_completion_is_not_current_proof(completed: str) -> None:
    assert not evaluate(
        ledger(),
        [evidence() | {"completed_at": completed}],
        slot=600,
        group_id="sg-1",
        account_id="123456789012",
        region="sa-east-1",
        safe=True,
    )
