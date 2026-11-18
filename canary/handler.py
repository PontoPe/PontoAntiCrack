"""Create one real EC2 ingress event per five-minute slot, after a snapshot.

No ENI or instance may use this SG. Replays do not authorize again, even after
partial failure. The ledger is NOT proof that remediation ran. No rollback
reopens access; a stuck canary is an incident requiring scoped reconciliation.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

from remediations.common.aws import AwsClients
from remediations.sg_open.scope import Scope, ScopeError

PERIOD = 300
SSH_WORLD = {
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
}


def key(scope: Scope, slot: int) -> dict[str, str]:
    return {"pk": f"CANARY#{scope.round_id}", "sk": str(slot).zfill(12)}


def ssh_open(group: dict[str, Any]) -> bool:
    for rule in group.get("IpPermissions", []):
        protocol = str(rule.get("IpProtocol"))
        ports = protocol == "-1" or (
            protocol in {"tcp", "6"}
            and int(rule.get("FromPort", 0)) <= 22 <= int(rule.get("ToPort", 65535))
        )
        world = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
        world |= any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
        if ports and world:
            return True
    return False


def produce(scope: Scope, aws: AwsClients, table: Any, *, now: int) -> bool:
    slot = now // PERIOD * PERIOD
    # The durable claim precedes inspecting state: a replay after the first
    # authorize must not fail as a fresh attack or overwrite its ledger.
    existing = table.get_item(Key=key(scope, slot), ConsistentRead=True).get("Item")
    if existing:
        return False
    group = scope.inspect(aws, scope.group_id)
    if ssh_open(dict(group)):
        raise ScopeError("previous world-open SSH has not converged; refusing new canary")
    try:
        table.put_item(
            Item={
                **key(scope, slot),
                "slot": slot,
                "status": "PLANNED",
                "snapshot": json.dumps(dict(group), default=str, sort_keys=True),
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise
    # Recheck eligibility after the durable write. No IAM CreateTags capability
    # is granted to either scheduled function.
    scope.inspect(aws, scope.group_id)
    response = aws.ec2.authorize_security_group_ingress(
        GroupId=scope.group_id, IpPermissions=[SSH_WORLD]
    )
    request_id = response["ResponseMetadata"]["RequestId"]
    table.update_item(
        Key=key(scope, slot),
        UpdateExpression="SET #s = :s, request_id = :r",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "ISSUED", ":r": request_id},
    )
    return True


def schedule_time(event: dict[str, Any], *, now: float) -> int:
    """Refuse stale/future invocations before creating clients or claiming a slot."""
    try:
        scheduled = datetime.fromisoformat(event["time"].replace("Z", "+00:00"))
        if scheduled.tzinfo is None:
            raise ValueError("schedule must include timezone")
        epoch = scheduled.timestamp()
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ValueError("invalid schedule timestamp") from exc
    if (
        event.get("source") != "aws.events"
        or event.get("detail-type") != "Scheduled Event"
        or not 0 <= now - epoch <= 60
    ):
        raise ValueError("invalid or expired schedule")
    return int(epoch)


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, bool]:
    scheduled = schedule_time(event, now=time.time())
    scope = Scope.from_env()
    aws = AwsClients(region_name=scope.region)
    return {"issued": produce(scope, aws, aws.table(os.environ["PAC_TABLE_NAME"]), now=scheduled)}
