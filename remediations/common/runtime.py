"""The pipeline every detection runs through.

Order is the security property here, so it is stated once, in one place:

1. reject events this system itself caused (loop prevention)
2. plan — read-only inspection; ``None`` means benign, stop
3. honour the exclusion tag — stop before touching anything
4. **write the snapshot to the audit table** — before any mutation
5. count the attempt against the circuit breaker; if open, stop
6. if dry-run, stop
7. apply
8. close the audit record and alert

Steps 4 and 7 cannot be reordered by a handler, because handlers do not call
either of them.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from remediations.common import events as event_parser
from remediations.common.audit import AuditLog
from remediations.common.aws import AwsClients
from remediations.common.circuit_breaker import CircuitBreaker
from remediations.common.config import Config
from remediations.common.detection import Detection
from remediations.common.models import DetectionEvent, Outcome, Plan, Severity, Status

log = logging.getLogger("pac")


class Notifier(Protocol):
    """What the runtime needs from an alerting backend."""

    def notify(self, event: DetectionEvent, outcome: Outcome, plan: Plan | None) -> bool:
        """Send the alert. Returns False when suppressed as a duplicate."""
        ...


class NullNotifier:
    """Used when no webhook secret is configured. Logs and moves on."""

    def notify(self, event: DetectionEvent, outcome: Outcome, plan: Plan | None) -> bool:
        log.info(
            "alert suppressed: no notifier configured",
            extra={"detection": outcome.detection_id, "status": outcome.status.value},
        )
        return False


def execute(
    detection: Detection,
    raw_event: dict[str, Any],
    config: Config,
    aws: AwsClients,
    notifier: Notifier,
) -> Outcome:
    event = event_parser.parse(raw_event)
    table = aws.table(config.table_name)
    audit = AuditLog(table, config.detection_id)

    # 1. Loop prevention. Our own remediation calls are themselves CloudTrail
    #    events that match our own patterns.
    if event.principal.is_pac_automation():
        outcome = _skip(config, "triggered by this system's own remediation role")
        audit.record_unplanned(event, outcome)
        return outcome

    # 2. Plan. Read-only.
    plan = detection.plan(event, aws)
    if plan is None:
        outcome = _skip(config, "resource state is not dangerous", severity=Severity.INFO)
        audit.record_unplanned(event, outcome)
        return outcome

    # 3. Exclusion tag. Checked before the audit write only because there is
    #    nothing to roll back — but it is still alerted on: an excluded resource
    #    going public is a decision someone made, and it should be visible.
    if config.exclusion_tag in plan.tags:
        outcome = Outcome(
            detection_id=config.detection_id,
            status=Status.SKIPPED,
            severity=Severity.MEDIUM,
            resource_id=plan.resource_id,
            reason=(
                f"excluded by tag {config.exclusion_tag}="
                f"{plan.tags[config.exclusion_tag]!r}; {plan.reason}"
            ),
        )
        audit.record_unplanned(event, outcome)
        notifier.notify(event, outcome, plan)
        return outcome

    # 4. Snapshot first. Everything after this point can fail without losing
    #    the original resource state.
    key = audit.open(event, plan, dry_run=config.dry_run)

    # 4b. A plan with no intended actions is a handler saying "this is real, and
    #     a human has to do it". It takes no action, so it does not count
    #     against the breaker.
    if not plan.intended_actions:
        outcome = Outcome(
            detection_id=config.detection_id,
            status=Status.ESCALATED,
            severity=plan.severity,
            resource_id=plan.resource_id,
            reason=plan.reason,
        )
        audit.close(key, outcome)
        notifier.notify(event, outcome, plan)
        return outcome

    # 5. Circuit breaker.
    breaker = CircuitBreaker(
        table,
        config.detection_id,
        limit=config.circuit_breaker_max_actions,
        window_seconds=config.circuit_breaker_window_seconds,
    )
    state = breaker.check_and_increment()
    if state.open:
        outcome = Outcome(
            detection_id=config.detection_id,
            status=Status.BLOCKED,
            severity=Severity.CRITICAL,
            resource_id=plan.resource_id,
            reason=state.reason,
        )
        audit.close(key, outcome)
        notifier.notify(event, outcome, plan)
        return outcome

    # 6. Dry run.
    if config.dry_run:
        outcome = Outcome(
            detection_id=config.detection_id,
            status=Status.DRY_RUN,
            severity=plan.severity,
            resource_id=plan.resource_id,
            reason=plan.reason,
            actions=tuple(plan.intended_actions),
        )
        audit.close(key, outcome)
        notifier.notify(event, outcome, plan)
        return outcome

    # 7. Apply.
    try:
        actions = detection.apply(plan, aws)
    except Exception as exc:  # noqa: BLE001 - a failed remediation must alert, not crash
        outcome = Outcome(
            detection_id=config.detection_id,
            status=Status.FAILED,
            severity=Severity.CRITICAL,
            resource_id=plan.resource_id,
            reason=plan.reason,
            actions=tuple(plan.intended_actions),
            error=f"{type(exc).__name__}: {exc}",
        )
        audit.close(key, outcome)
        notifier.notify(event, outcome, plan)
        log.exception("remediation failed", extra={"detection": config.detection_id})
        return outcome

    # 8. Close out.
    outcome = Outcome(
        detection_id=config.detection_id,
        status=Status.APPLIED,
        severity=plan.severity,
        resource_id=plan.resource_id,
        reason=plan.reason,
        actions=tuple(actions),
    )
    audit.close(key, outcome)
    notifier.notify(event, outcome, plan)
    return outcome


def _skip(config: Config, reason: str, severity: Severity = Severity.LOW) -> Outcome:
    return Outcome(
        detection_id=config.detection_id,
        status=Status.SKIPPED,
        severity=severity,
        resource_id="none",
        reason=reason,
    )
