"""Partial producer failures retain claims; later pages cannot hide ambiguity."""

from typing import Any
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from canary.handler import SSH_WORLD, key, produce, ssh_open
from canary.observer import observe
from tests.canary.test_heartbeat import evidence, ledger
from tests.remediations.test_sg_scope import scoped


@pytest.mark.parametrize("failure", ["inspect", "authorize", "update"])
def test_partial_failure_never_reauthorizes(aws: Any, audit_table: Any, failure: str) -> None:
    detection, group = scoped(aws)
    aws.ec2.revoke_security_group_ingress(GroupId=group, IpPermissions=[SSH_WORLD])
    scope = Mock(wraps=detection.scope)
    scope.round_id = detection.scope.round_id
    scope.group_id = group
    authorize = Mock(wraps=aws.ec2.authorize_security_group_ingress)
    aws.ec2.authorize_security_group_ingress = authorize
    table = Mock(wraps=audit_table)
    if failure == "inspect":
        safe = detection.scope.inspect(aws, group)
        scope.inspect.side_effect = [safe, RuntimeError("injected inspect")]
    elif failure == "authorize":
        authorize.side_effect = RuntimeError("injected authorize")
    else:
        table.update_item.side_effect = RuntimeError("injected update")
    with pytest.raises(RuntimeError, match=f"injected {failure}"):
        produce(scope, aws, table, now=600)
    row = audit_table.get_item(Key=key(detection.scope, 600))["Item"]
    assert row["status"] == "PLANNED"
    assert "snapshot" in row
    assert not produce(scope, aws, table, now=601)
    assert audit_table.get_item(Key=key(detection.scope, 600))["Item"] == row
    assert authorize.call_count == (0 if failure == "inspect" else 1)
    current = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]
    assert ssh_open(current) is (failure == "update")


def test_lost_conditional_claim_cannot_authorize(aws: Any) -> None:
    detection, group = scoped(aws)
    aws.ec2.revoke_security_group_ingress(GroupId=group, IpPermissions=[SSH_WORLD])
    aws.ec2.authorize_security_group_ingress = Mock()
    table = Mock()
    table.get_item.return_value = {}
    table.put_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem"
    )
    assert not produce(detection.scope, aws, table, now=600)
    aws.ec2.authorize_security_group_ingress.assert_not_called()
    table.update_item.assert_not_called()


def test_unresolved_record_on_later_page_blocks_success() -> None:
    scope, aws, table = Mock(), Mock(), Mock()
    scope.round_id = "round"
    scope.group_id = "sg-1"
    scope.account_id = "123456789012"
    scope.region = "sa-east-1"
    scope.inspect.return_value = {"IpPermissions": []}
    table.get_item.return_value = {"Item": ledger()}
    token = {"pk": "audit-partition", "sk": "next"}
    table.query.side_effect = [
        {"Items": [evidence()], "LastEvaluatedKey": token},
        {"Items": [evidence() | {"status": "PLANNED"}]},
    ]
    assert not observe(scope, aws, table, now=840)
    assert table.query.call_count == 2
    assert table.query.call_args.kwargs["ExclusiveStartKey"] == token
    metric = aws.client.return_value.put_metric_data.call_args.kwargs["MetricData"][0]
    assert metric["Value"] == 0
