"""One place that knows what time it is, so tests can be deterministic."""

from __future__ import annotations

from datetime import UTC, datetime


def now() -> datetime:
    return datetime.now(UTC)


def iso(moment: datetime | None = None) -> str:
    return (moment or now()).isoformat().replace("+00:00", "Z")


def epoch(moment: datetime | None = None) -> int:
    return int((moment or now()).timestamp())
