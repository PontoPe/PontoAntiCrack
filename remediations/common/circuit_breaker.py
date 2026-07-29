"""Per-detection circuit breaker.

Threat R2: an attacker who can generate the events a detection watches for can
turn auto-remediation into a denial of service — mass-revoking production
security group rules by opening and re-opening them, for instance. The breaker
caps how many remediations one detection may perform inside a rolling window
and then refuses, loudly, instead of continuing.

State lives in the same DynamoDB table as the audit trail so there is no second
thing to provision and no second thing to keep consistent. Counters carry a TTL;
audit records do not.

This is a per-detection *behavioural* limit. The infrastructure-level limit —
Lambda ``reserved_concurrent_executions`` — is separate and complementary: it
caps how fast we can be invoked, this caps how much damage an invocation storm
is allowed to do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from remediations.common import clock

BREAKER_PREFIX = "CB"


@dataclass(frozen=True, slots=True)
class BreakerState:
    open: bool
    count: int
    limit: int
    window_start: int
    window_seconds: int

    @property
    def reason(self) -> str:
        return (
            f"circuit breaker open: {self.count} remediation attempts by this detection "
            f"in the last {self.window_seconds}s exceeds the limit of {self.limit}"
        )


class CircuitBreaker:
    def __init__(self, table: Any, detection_id: str, *, limit: int, window_seconds: int) -> None:
        self._table = table
        self._detection_id = detection_id
        self._limit = limit
        self._window_seconds = window_seconds

    def _window_start(self, at: int) -> int:
        return at - (at % self._window_seconds)

    def check_and_increment(self, at: int | None = None) -> BreakerState:
        """Count this attempt and report whether the breaker is now open.

        The increment happens in dry-run too. A dry-run deployment that would
        have tripped the breaker is exactly the signal you want before turning
        remediation on, and hiding it defeats the purpose of the dry run.
        """
        moment = clock.epoch() if at is None else at
        window_start = self._window_start(moment)

        response = self._table.update_item(
            Key={
                "pk": f"{BREAKER_PREFIX}#{self._detection_id}",
                "sk": f"WINDOW#{window_start}",
            },
            UpdateExpression="ADD attempts :one SET expires_at = :ttl, detection_id = :did",
            ExpressionAttributeValues={
                ":one": 1,
                # Two windows of slack so the item is still readable while the
                # window it describes is being investigated.
                ":ttl": window_start + (self._window_seconds * 2),
                ":did": self._detection_id,
            },
            ReturnValues="UPDATED_NEW",
        )
        count = int(response.get("Attributes", {}).get("attempts", 1))

        return BreakerState(
            open=count > self._limit,
            count=count,
            limit=self._limit,
            window_start=window_start,
            window_seconds=self._window_seconds,
        )
