"""Simulated protocol across producer, runtime, audit query and metrics (moto).

A locally adapted CloudTrail fixture bridges services; this is NOT proof of
CloudTrail/EventBridge delivery, IAM enforcement or CloudWatch alarm delivery.
"""

from typing import Any

import pytest

from canary.handler import SSH_WORLD, key, produce, ssh_open
from canary.observer import observe
from remediations.common.aws import AwsClients
from remediations.common.runtime import execute
from tests.conftest import RecordingNotifier, load_event, make_config
from tests.remediations.test_sg_scope import scoped


@pytest.mark.parametrize("dry_run", [True, False])
def test_full_simulated_protocol(
    aws: AwsClients,
    audit_table: Any,
    notifier: RecordingNotifier,
    monkeypatch: pytest.MonkeyPatch,
    dry_run: bool,
) -> None:
    detection, group = scoped(aws)
    aws.ec2.revoke_security_group_ingress(GroupId=group, IpPermissions=[SSH_WORLD])
    assert produce(detection.scope, aws, audit_table, now=600)
    row = audit_table.get_item(Key=key(detection.scope, 600))["Item"]
    raw = load_event("cloudtrail", "sg-open", "authorize-ingress-ssh-world")
    raw["account"] = detection.scope.account_id
    raw["detail"]["requestParameters"]["groupId"] = group
    raw["detail"]["requestID"] = row["request_id"]
    raw["detail"]["eventTime"] = "1970-01-01T00:10:00Z"
    monkeypatch.setattr("remediations.common.audit.clock.iso", lambda: "1970-01-01T00:10:02Z")
    outcome = execute(
        detection, raw, make_config(detection_id="sg-open", dry_run=dry_run), aws, notifier
    )
    assert outcome.status.value == ("DRY_RUN" if dry_run else "APPLIED")
    current = aws.ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]
    assert ssh_open(current) is dry_run
    assert observe(detection.scope, aws, audit_table, now=840) is not dry_run
    # Replays neither authorize again nor overwrite the producer claim.
    assert not produce(detection.scope, aws, audit_table, now=601)
    assert audit_table.get_item(Key=key(detection.scope, 600))["Item"] == row


def test_missing_path_is_unhealthy_even_after_external_correction(
    aws: AwsClients,
    audit_table: Any,
) -> None:
    detection, group = scoped(aws)
    aws.ec2.revoke_security_group_ingress(GroupId=group, IpPermissions=[SSH_WORLD])
    assert produce(detection.scope, aws, audit_table, now=600)
    assert not observe(detection.scope, aws, audit_table, now=840)
    aws.ec2.revoke_security_group_ingress(GroupId=group, IpPermissions=[SSH_WORLD])
    assert not observe(detection.scope, aws, audit_table, now=841)
