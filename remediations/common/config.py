"""Environment-driven configuration.

Nothing here reads a secret value. ``PAC_SLACK_SECRET_ARN`` is an ARN, not a
webhook — the webhook itself is fetched from Secrets Manager at call time so it
never appears in the function configuration, in CloudTrail's
``UpdateFunctionConfiguration`` request parameters, or in a `terraform show`.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


class ConfigError(RuntimeError):
    """Raised when the function is wired up wrong. Fail loudly at cold start."""


def _flag(env: Mapping[str, str], name: str, *, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    lowered = raw.strip().lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    raise ConfigError(f"{name}={raw!r} is not a boolean")


def _positive_int(env: Mapping[str, str], name: str, *, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}={raw!r} is not an integer") from exc
    if value <= 0:
        raise ConfigError(f"{name}={value} must be positive")
    return value


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved function configuration."""

    detection_id: str
    table_name: str
    environment: str
    dry_run: bool
    exclusion_tag: str
    circuit_breaker_max_actions: int
    circuit_breaker_window_seconds: int
    dedup_window_seconds: int
    slack_secret_arn: str | None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        source: Mapping[str, str] = os.environ if env is None else env

        detection_id = source.get("PAC_DETECTION_ID", "").strip()
        if not detection_id:
            raise ConfigError("PAC_DETECTION_ID is required")

        table_name = source.get("PAC_TABLE_NAME", "").strip()
        if not table_name:
            raise ConfigError("PAC_TABLE_NAME is required")

        slack_secret_arn = source.get("PAC_SLACK_SECRET_ARN", "").strip() or None

        return cls(
            detection_id=detection_id,
            table_name=table_name,
            environment=source.get("PAC_ENVIRONMENT", "unknown").strip() or "unknown",
            # Dry-run is the default. A missing or malformed variable must never
            # be the reason production resources start getting modified, so the
            # only way to take real action is to say so explicitly.
            dry_run=_flag(source, "PAC_DRY_RUN", default=True),
            exclusion_tag=source.get("PAC_EXCLUSION_TAG", "pac:exclude").strip() or "pac:exclude",
            circuit_breaker_max_actions=_positive_int(
                source, "PAC_CIRCUIT_BREAKER_MAX_ACTIONS", default=5
            ),
            circuit_breaker_window_seconds=_positive_int(
                source, "PAC_CIRCUIT_BREAKER_WINDOW_SECONDS", default=300
            ),
            dedup_window_seconds=_positive_int(source, "PAC_DEDUP_WINDOW_SECONDS", default=900),
            slack_secret_arn=slack_secret_arn,
        )
