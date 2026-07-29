"""The audit table: what we saw, what the resource looked like, what we did.

The ordering constraint this module exists to enforce: :meth:`AuditLog.open` is
called with the pre-change snapshot **before** the handler touches anything, and
:meth:`AuditLog.close` updates the same item afterwards. If the function is
killed between the two — throttled, timed out, out of memory — the snapshot has
already survived, and incident response still has the original resource state.

Records have no TTL. They are the rollback source and the evidence trail.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from remediations.common import clock, redact
from remediations.common.models import DetectionEvent, Outcome, Plan

AUDIT_PREFIX = "AUDIT"


def audit_key(
    detection_id: str, resource_id: str, event_time: str, event_id: str
) -> dict[str, str]:
    return {
        "pk": f"{AUDIT_PREFIX}#{detection_id}#{resource_id}",
        "sk": f"{event_time}#{event_id}",
    }


class AuditLog:
    """Two-phase writer over the DynamoDB audit table."""

    def __init__(self, table: Any, detection_id: str) -> None:
        self._table = table
        self._detection_id = detection_id

    def open(self, event: DetectionEvent, plan: Plan, *, dry_run: bool) -> Mapping[str, str]:
        """Persist the pre-change snapshot. Returns the item key."""
        key = audit_key(self._detection_id, plan.resource_id, event.event_time, event.event_id)
        item: dict[str, Any] = {
            **key,
            "detection_id": self._detection_id,
            # PLANNED is intentionally not a terminal Status: an item left in
            # this state means the function died mid-remediation, which is worth
            # being able to query for.
            "status": "PLANNED",
            "recorded_at": clock.iso(),
            "dry_run": dry_run,
            "severity": plan.severity.value,
            "reason": plan.reason,
            "resource_id": plan.resource_id,
            "resource_arn": plan.resource_arn,
            "account_id": event.account_id,
            "region": event.region,
            "event_id": event.event_id,
            "event_time": event.event_time,
            "event_source": event.source,
            "principal_arn": event.principal.arn,
            "principal_type": event.principal.type,
            "principal_name": event.principal.name,
            "source_ip": event.source_ip,
            "user_agent": event.user_agent,
            "intended_actions": list(plan.intended_actions),
            "tags": dict(redact.scrub(plan.tags)),
            "blast_radius": _dump(plan.blast_radius),
            # Serialised rather than stored as a document: bucket policies and
            # security group rule sets contain empty strings and nested numbers
            # that DynamoDB either rejects or silently coerces. A JSON string
            # round-trips byte for byte, which is what evidence has to do.
            "snapshot": _dump(plan.snapshot),
        }
        self._table.put_item(Item=item)
        return key

    def close(self, key: Mapping[str, str], outcome: Outcome) -> None:
        """Record the terminal state against the item opened earlier."""
        expression = (
            "SET #s = :status, actions = :actions, completed_at = :completed, "
            "outcome_reason = :reason, #e = :error"
        )
        self._table.update_item(
            Key=dict(key),
            UpdateExpression=expression,
            ExpressionAttributeNames={"#s": "status", "#e": "error"},
            ExpressionAttributeValues={
                ":status": outcome.status.value,
                ":actions": list(outcome.actions),
                ":completed": clock.iso(),
                ":reason": outcome.reason,
                ":error": outcome.error,
            },
        )

    def record_unplanned(self, event: DetectionEvent, outcome: Outcome) -> None:
        """Record an invocation that never produced a plan.

        Skips and self-triggered loops still belong in the table — "nothing
        happened" is only credible if it was written down.
        """
        key = audit_key(
            self._detection_id, outcome.resource_id or "none", event.event_time, event.event_id
        )
        self._table.put_item(
            Item={
                **key,
                "detection_id": self._detection_id,
                "status": outcome.status.value,
                "recorded_at": clock.iso(),
                "severity": outcome.severity.value,
                "reason": outcome.reason,
                "resource_id": outcome.resource_id,
                "account_id": event.account_id,
                "region": event.region,
                "event_id": event.event_id,
                "event_time": event.event_time,
                "event_source": event.source,
                "principal_arn": event.principal.arn,
                "source_ip": event.source_ip,
                "actions": list(outcome.actions),
                "error": outcome.error,
            }
        )


def _dump(value: Any) -> str:
    return json.dumps(redact.scrub(value), default=str, sort_keys=True)
