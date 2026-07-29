"""The contract every detection implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from remediations.common.aws import AwsClients
from remediations.common.models import DetectionEvent, Plan, Severity


class Detection(ABC):
    """Two questions, deliberately separated.

    ``plan`` answers "is this resource actually dangerous, and what is the
    minimal fix?" — read-only, and it gathers the snapshot that must be durable
    before anything changes. ``apply`` answers "make it so" and is the only
    method allowed to mutate.

    Returning ``None`` from ``plan`` is the benign case: the event matched the
    pattern but the resulting state is fine. That is the normal, expected
    outcome for a coarse pattern, and it must never be treated as an error.
    """

    id: ClassVar[str]
    default_severity: ClassVar[Severity] = Severity.HIGH

    @abstractmethod
    def plan(self, event: DetectionEvent, aws: AwsClients) -> Plan | None:
        """Inspect the resource. No writes. Returns ``None`` if benign."""

    @abstractmethod
    def apply(self, plan: Plan, aws: AwsClients) -> list[str]:
        """Perform the remediation. Returns a human-readable action list."""
