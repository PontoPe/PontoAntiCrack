"""The deployed SG handler refuses anything outside its explicit lab scope."""

from dataclasses import replace
from unittest.mock import Mock

import pytest

from remediations.common.aws import AwsClients
from remediations.sg_open.scope import GuardedSgOpen, Scope, ScopeError
from tests.conftest import seed_security_group
from tests.remediations.test_sg_open_handler import _event, _ssh_world


def scoped(aws: AwsClients) -> tuple[GuardedSgOpen, str]:
    group = seed_security_group(aws, permissions=[_ssh_world()], tags={"pac:canary": "round-1"})
    account = aws.client("sts").get_caller_identity()["Account"]
    return GuardedSgOpen(Scope(account, "sa-east-1", group, "round-1")), group


def test_scope_checks_account_before_ec2(aws: AwsClients) -> None:
    detection, group = scoped(aws)
    aws.ec2.describe_security_groups = Mock(side_effect=AssertionError("must not read EC2"))
    with pytest.raises(ScopeError, match="account/region"):
        detection.plan(_event(group), aws)


def test_eligible_resource_can_be_remediated(aws: AwsClients) -> None:
    detection, group = scoped(aws)
    event = replace(_event(group), account_id=detection.scope.account_id)
    plan = detection.plan(event, aws)
    assert plan is not None
    assert detection.apply(plan, aws)


@pytest.mark.parametrize("change", ["tag", "exclude", "attachment"])
def test_apply_rechecks_eligibility(aws: AwsClients, change: str) -> None:
    detection, group = scoped(aws)
    event = replace(_event(group), account_id=detection.scope.account_id)
    plan = detection.plan(event, aws)
    assert plan is not None
    if change == "tag":
        aws.ec2.delete_tags(Resources=[group], Tags=[{"Key": "pac:canary"}])
    elif change == "exclude":
        aws.ec2.create_tags(Resources=[group], Tags=[{"Key": "pac:exclude", "Value": ""}])
    else:
        aws.ec2.describe_network_interfaces = Mock(return_value={"NetworkInterfaces": [{}]})
    aws.ec2.revoke_security_group_ingress = Mock()
    with pytest.raises(ScopeError):
        detection.apply(plan, aws)
    aws.ec2.revoke_security_group_ingress.assert_not_called()


def test_missing_deployed_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PAC_SCOPE_ACCOUNT", raising=False)
    with pytest.raises(ScopeError):
        Scope.from_env()
