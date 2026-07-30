"""Slack alerts with enough context to act on without opening the console.

Every alert answers: which detection, which resource, who did it, from where,
how bad, what we did about it, and how to undo it. Threat R7 says an alert that
does not answer those is noise.

Nothing credential-bearing is ever formatted into the message — the payload is
passed through :mod:`remediations.common.redact` on the way out, and the webhook
URL itself is fetched from Secrets Manager per container and never logged.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

from notifier.dedup import Deduplicator, fingerprint
from remediations.common import redact
from remediations.common.models import DetectionEvent, Outcome, Plan, Severity, Status

log = logging.getLogger("pac.notifier")

_TIMEOUT_SECONDS = 5

_SEVERITY_EMOJI = {
    Severity.INFO: ":information_source:",
    Severity.LOW: ":white_circle:",
    Severity.MEDIUM: ":large_yellow_circle:",
    Severity.HIGH: ":large_orange_circle:",
    Severity.CRITICAL: ":red_circle:",
}

_STATUS_HEADLINE = {
    Status.APPLIED: "remediated",
    Status.DRY_RUN: "would remediate (dry run)",
    Status.SKIPPED: "no action",
    Status.ESCALATED: "MANUAL ACTION REQUIRED",
    Status.BLOCKED: "remediation BLOCKED",
    Status.FAILED: "remediation FAILED",
}


class SlackNotifier:
    def __init__(
        self,
        secret_arn: str,
        aws: Any,
        table: Any,
        environment: str,
        dedup_window_seconds: int,
    ) -> None:
        self._secret_arn = secret_arn
        self._aws = aws
        self._environment = environment
        self._dedup = Deduplicator(table, dedup_window_seconds)
        self._webhook: str | None = None

    def notify(self, event: DetectionEvent, outcome: Outcome, plan: Plan | None) -> bool:
        key = fingerprint(
            outcome.detection_id,
            outcome.resource_id,
            outcome.status.value,
            outcome.severity.value,
        )
        if not self._dedup.claim(key):
            log.info("alert suppressed as duplicate", extra={"fingerprint": key})
            return False

        payload = build_payload(event, outcome, plan, self._environment)
        self._post(payload)
        return True

    def _resolve_webhook(self) -> str | None:
        """Return the webhook, or None if it cannot be read or is unusable.

        A secret with no version, an unparseable value or a non-https URL is as
        undeliverable as a network failure, and the reasoning below applies to
        all of them equally: the remediation has already happened by the time
        this runs. Raising here would fail an invocation that succeeded, and on
        an EventBridge retry it would run the remediation a second time.
        """
        if self._webhook is None:
            try:
                response = self._aws.secretsmanager.get_secret_value(SecretId=self._secret_arn)
                candidate = _extract_webhook(response.get("SecretString", ""))
            except Exception as exc:  # noqa: BLE001 - any read failure is undeliverable
                log.error("slack webhook could not be read: %s", type(exc).__name__)
                return None
            if not candidate.startswith("https://"):
                log.error("slack webhook is not an https URL; alert not delivered")
                return None
            self._webhook = candidate
        return self._webhook

    def _post(self, payload: dict[str, Any]) -> None:
        webhook = self._resolve_webhook()
        if webhook is None:
            return

        request = urllib.request.Request(  # noqa: S310 - scheme asserted https above
            webhook,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
                if response.status >= 300:
                    log.error("slack rejected the alert: HTTP %s", response.status)
        except urllib.error.URLError as exc:
            # An undeliverable alert must not undo a completed remediation, and
            # must not cause a retry that re-runs one. Log and let the caller
            # finish; CloudWatch alarms on this log line are the backstop.
            log.error("slack delivery failed: %s", exc)


def _extract_webhook(raw: str) -> str:
    """Accept either a bare URL or ``{"webhook_url": "..."}``."""
    stripped = raw.strip()
    if stripped.startswith("{"):
        parsed = json.loads(stripped)
        value = parsed.get("webhook_url") or parsed.get("url") or ""
        return str(value).strip()
    return stripped


def build_payload(
    event: DetectionEvent,
    outcome: Outcome,
    plan: Plan | None,
    environment: str,
) -> dict[str, Any]:
    """Render the Slack message. Pure — this is what the tests assert on."""
    emoji = _SEVERITY_EMOJI.get(outcome.severity, ":white_circle:")
    headline = _STATUS_HEADLINE.get(outcome.status, outcome.status.value)
    title = f"{emoji} [{environment}] {outcome.detection_id} — {headline}"

    fields = [
        ("Resource", outcome.resource_id),
        ("Account", f"{event.account_id} ({event.region})"),
        ("Principal", event.principal.arn),
        ("Source IP", event.source_ip),
        ("Severity", outcome.severity.value),
        ("Event", f"{event.source} / {event.event_id}"),
    ]
    if plan is not None and plan.blast_radius:
        fields.append(("Blast radius", _render_blast_radius(plan.blast_radius)))

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": _plain(title)}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*{label}*\n{_code(value)}"} for label, value in fields
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Why*\n{_plain(outcome.reason)}"},
        },
    ]

    if outcome.actions:
        rendered = "\n".join(f"• {_plain(action)}" for action in outcome.actions)
        label = "Actions taken" if outcome.status is Status.APPLIED else "Actions withheld"
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{label}*\n{rendered}"}}
        )

    if outcome.error:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Error*\n{_code(outcome.error)}"},
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"Prior state snapshotted to the audit table before any change · "
                        f"event time {_plain(event.event_time)}"
                    ),
                }
            ],
        }
    )

    return redact.scrub_mapping({"text": title, "blocks": blocks})


def _render_blast_radius(blast_radius: Any) -> str:
    # Scrub before flattening, not after. Once `secretAccessKey: <value>` has
    # been rendered into the string "secretAccessKey=<value>", key-based
    # redaction has nothing left to match on.
    if isinstance(blast_radius, Mapping):
        scrubbed = redact.scrub_mapping(blast_radius)
        return ", ".join(f"{key}={value}" for key, value in sorted(scrubbed.items()))
    return str(redact.scrub(blast_radius))


def _plain(value: Any) -> str:
    return redact.scrub_text(str(value))


def _code(value: Any) -> str:
    text = _plain(value)
    return f"`{text}`" if text else "`—`"
