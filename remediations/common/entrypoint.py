"""Wire a :class:`Detection` into a Lambda handler.

Config, clients, and the Slack secret are resolved once per container and reused
across warm invocations. Config errors raise at first invocation rather than
being swallowed — a misconfigured detection must fail visibly, not run in some
half-defined mode.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from typing import Any

from remediations.common.aws import AwsClients
from remediations.common.config import Config
from remediations.common.detection import Detection
from remediations.common.models import Outcome
from remediations.common.runtime import Notifier, NullNotifier, execute

log = logging.getLogger("pac")
if not log.handlers:
    logging.basicConfig(level=os.environ.get("PAC_LOG_LEVEL", "INFO"))


class _Container:
    """Per-container state. Reset in tests by constructing a new one."""

    def __init__(self) -> None:
        self.config: Config | None = None
        self.aws: AwsClients | None = None
        self.notifier: Notifier | None = None

    def resolve(self) -> tuple[Config, AwsClients, Notifier]:
        if self.config is None:
            self.config = Config.from_env()
        if self.aws is None:
            self.aws = AwsClients()
        if self.notifier is None:
            self.notifier = _build_notifier(self.config, self.aws)
        return self.config, self.aws, self.notifier


def _build_notifier(config: Config, aws: AwsClients) -> Notifier:
    if not config.slack_secret_arn:
        return NullNotifier()
    # Imported here so a function with no webhook configured never pays the
    # import cost, and so the notifier stays an optional dependency of the
    # remediation path rather than a required one.
    from notifier.slack import SlackNotifier

    return SlackNotifier(
        secret_arn=config.slack_secret_arn,
        aws=aws,
        table=aws.table(config.table_name),
        environment=config.environment,
        dedup_window_seconds=config.dedup_window_seconds,
    )


def build(detection: Detection) -> Callable[[dict[str, Any], Any], dict[str, Any]]:
    """Return the ``lambda_handler`` for ``detection``."""
    container = _Container()

    def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
        config, aws, notifier = container.resolve()
        outcome = execute(detection, event, config, aws, notifier)
        log.info("pac outcome %s", json.dumps(_summary(outcome)))
        return _summary(outcome)

    return lambda_handler


def _summary(outcome: Outcome) -> dict[str, Any]:
    return {
        "detection": outcome.detection_id,
        "status": outcome.status.value,
        "severity": outcome.severity.value,
        "resource": outcome.resource_id,
        "reason": outcome.reason,
        "actions": list(outcome.actions),
        "error": outcome.error,
    }
