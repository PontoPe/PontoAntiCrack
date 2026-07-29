"""Alert deduplication.

Threat R7 is alert fatigue. An attacker re-opening the same security group in a
loop produces one alert per attempt, and the twentieth is the one nobody reads.

The window is enforced with a conditional write to the audit table: the first
caller to claim a fingerprint sends, everyone else inside the window is
suppressed. Conditional writes are atomic, so two concurrent Lambda invocations
cannot both decide they are first.
"""

from __future__ import annotations

import hashlib
from typing import Any

from remediations.common import clock

DEDUP_PREFIX = "DEDUP"


def fingerprint(detection_id: str, resource_id: str, status: str, severity: str) -> str:
    """Identity of an alert for suppression purposes.

    Status is part of the key on purpose: a resource that was skipped and then
    later actually remediated is a different thing to know about, and must not
    be swallowed by the earlier alert's window.
    """
    material = "|".join((detection_id, resource_id, status, severity))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


class Deduplicator:
    def __init__(self, table: Any, window_seconds: int) -> None:
        self._table = table
        self._window_seconds = window_seconds

    def claim(self, key: str, at: int | None = None) -> bool:
        """True if this caller should send; False if it is a duplicate."""
        now = clock.epoch() if at is None else at
        try:
            self._table.put_item(
                Item={
                    "pk": f"{DEDUP_PREFIX}#{key}",
                    "sk": "ALERT",
                    "expires_at": now + self._window_seconds,
                    "claimed_at": clock.iso(),
                },
                # The window is enforced by the condition, not by the TTL.
                # DynamoDB deletes expired items on its own schedule — typically
                # within 48 hours, not within the 15 minutes we want — so
                # relying on TTL for correctness would suppress alerts for the
                # rest of the day.
                ConditionExpression="attribute_not_exists(pk) OR expires_at < :now",
                ExpressionAttributeValues={":now": now},
            )
        except Exception as exc:  # noqa: BLE001 - boto3 raises a dynamic class
            if type(exc).__name__ == "ConditionalCheckFailedException":
                return False
            raise
        return True
