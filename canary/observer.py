"""Observer has no write permissions to EC2/audit and no invoke permission.

Success needs the same request ID, a terminal non-dry-run audit with real
revoke actions and a safe resource read. A missing ledger, delayed delivery,
or unresolved PLANNED record is unhealthy, never inferred successful. Shares
account, EC2, DynamoDB and CloudWatch with the system; not account-loss proof.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from boto3.dynamodb.conditions import Key

from canary.handler import PERIOD, key, schedule_time, ssh_open
from remediations.common.aws import AwsClients
from remediations.sg_open.scope import Scope


def iso(epoch: int) -> str:
    return (
        datetime.fromtimestamp(epoch, UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def evaluate(
    ledger: Mapping[str, Any] | None,
    audits: Sequence[Mapping[str, Any]],
    *,
    slot: int,
    group_id: str,
    account_id: str,
    region: str,
    safe: bool,
) -> bool:
    if (
        not safe
        or ledger is None
        or ledger.get("slot") != slot
        or ledger.get("status") != "ISSUED"
        or not ledger.get("request_id")
    ):
        return False
    correlated = [
        item
        for item in audits
        if item.get("request_id") == ledger["request_id"]
        and item.get("resource_id") == group_id
        and item.get("account_id") == account_id
        and item.get("region") == region
    ]
    # A later successful replay cannot resolve the forensic ambiguity left by
    # a delivery killed after opening its snapshot. Human reconciliation only.
    if any(item.get("status") in {"PLANNED", "FAILED"} for item in correlated):
        return False
    return any(
        item.get("status") == "APPLIED"
        and item.get("dry_run") is False
        and isinstance(item.get("actions"), list)
        and any(
            action == f"revoked ingress tcp/22-22 from 0.0.0.0/0 from {group_id}"
            for action in item["actions"]
        )
        and _within_window(item, slot)
        for item in correlated
    )


def _within_window(item: Mapping[str, Any], slot: int) -> bool:
    try:
        recorded = datetime.fromisoformat(item["recorded_at"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(item["completed_at"].replace("Z", "+00:00"))
        return (
            recorded.tzinfo is not None
            and completed.tzinfo is not None
            and slot <= recorded.timestamp() <= completed.timestamp() < slot + PERIOD
        )
    except (KeyError, TypeError, AttributeError, ValueError):
        return False


def observe(scope: Scope, aws: AwsClients, table: Any, *, now: int) -> bool:
    # Cron runs at minute 4 of each five-minute slot. Refuse late runs:
    # the 30s Lambda timeout must finish before the next producer can start.
    # Never judge an old slot against a newer probe's temporarily open SG.
    if not 240 <= now % PERIOD < 270:
        raise ValueError("outside nonoverlapping observation window")
    slot = now // PERIOD * PERIOD
    ledger = table.get_item(Key=key(scope, slot), ConsistentRead=True).get("Item")
    audits = []
    query: dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"AUDIT#sg-open#{scope.group_id}")
        & Key("sk").between(iso(slot), iso(slot + PERIOD)),
        "ConsistentRead": True,
    }
    while True:
        response = table.query(**query)
        audits.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        query["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    group = scope.inspect(aws, scope.group_id)
    healthy = evaluate(
        ledger,
        audits,
        slot=slot,
        group_id=scope.group_id,
        account_id=scope.account_id,
        region=scope.region,
        safe=not ssh_open(dict(group)),
    )
    aws.client("cloudwatch").put_metric_data(
        Namespace="PAC/Canary",
        MetricData=[
            {
                "MetricName": "EffectVerified",
                "Value": int(healthy),
                "Unit": "Count",
                "Dimensions": [{"Name": "Round", "Value": scope.round_id}],
            }
        ],
    )
    return healthy


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, bool]:
    now = int(time.time())
    schedule_time(event, now=now)
    scope = Scope.from_env()
    aws = AwsClients(region_name=scope.region)
    return {"healthy": observe(scope, aws, aws.table(os.environ["PAC_TABLE_NAME"]), now=now)}
