"""Controlled-clock canary protocol tests; no live AWS."""

from unittest.mock import Mock

import pytest

from canary.handler import produce
from canary.observer import evaluate
from remediations.common.aws import AwsClients
from tests.remediations.test_sg_scope import scoped


def test_producer_records_snapshot_before_authorize(aws: AwsClients, audit_table: object) -> None:
    detection, group = scoped(aws)
    aws.ec2.revoke_security_group_ingress(
        GroupId=group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    authorize = aws.ec2.authorize_security_group_ingress

    def checked(**kwargs: object) -> object:
        items = audit_table.scan()["Items"]
        assert len(items) == 1
        assert items[0]["status"] == "PLANNED"
        assert "snapshot" in items[0]
        return authorize(**kwargs)

    aws.ec2.authorize_security_group_ingress = Mock(side_effect=checked)
    produce(detection.scope, aws, audit_table, now=600)
    produce(detection.scope, aws, audit_table, now=601)
    assert aws.ec2.authorize_security_group_ingress.call_count == 1


def test_snapshot_failure_prevents_canary_mutation(aws: AwsClients) -> None:
    detection, group = scoped(aws)
    aws.ec2.revoke_security_group_ingress(
        GroupId=group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    aws.ec2.authorize_security_group_ingress = Mock()
    table = Mock()
    table.get_item.return_value = {}
    table.put_item.side_effect = RuntimeError("write unavailable")
    with pytest.raises(RuntimeError, match="write unavailable"):
        produce(detection.scope, aws, table, now=600)
    aws.ec2.authorize_security_group_ingress.assert_not_called()


def ledger() -> dict:
    return {"slot": 600, "request_id": "request-1", "status": "ISSUED"}


def evidence() -> dict:
    return {
        "request_id": "request-1",
        "status": "APPLIED",
        "resource_id": "sg-1",
        "account_id": "123456789012",
        "region": "sa-east-1",
        "dry_run": False,
        "actions": ["revoked ingress tcp/22-22 from 0.0.0.0/0 from sg-1"],
        "recorded_at": "1970-01-01T00:10:01Z",
        "completed_at": "1970-01-01T00:10:02Z",
    }


def test_only_correlated_effect_counts() -> None:
    assert evaluate(
        ledger(),
        [evidence()],
        slot=600,
        group_id="sg-1",
        account_id="123456789012",
        region="sa-east-1",
        safe=True,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "other"),
        ("status", "DRY_RUN"),
        ("status", "PLANNED"),
        ("resource_id", "sg-2"),
        ("account_id", "000000000000"),
        ("region", "us-east-1"),
        ("dry_run", True),
        ("actions", []),
        ("completed_at", "1970-01-01T00:09:59Z"),
    ],
)
def test_false_success_is_rejected(field: str, value: object) -> None:
    item = evidence() | {field: value}
    assert not evaluate(
        ledger(),
        [item],
        slot=600,
        group_id="sg-1",
        account_id="123456789012",
        region="sa-east-1",
        safe=True,
    )


def test_missing_stale_or_still_open_is_unhealthy() -> None:
    for row, safe in [(None, True), (ledger() | {"slot": 300}, True), (ledger(), False)]:
        assert not evaluate(
            row,
            [evidence()],
            slot=600,
            group_id="sg-1",
            account_id="123456789012",
            region="sa-east-1",
            safe=safe,
        )
