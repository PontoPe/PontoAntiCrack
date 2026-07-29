"""Value types passed between the runtime, the handlers, and the notifier."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    """Terminal state of one detection invocation."""

    APPLIED = "APPLIED"
    DRY_RUN = "DRY_RUN"
    SKIPPED = "SKIPPED"
    #: Dangerous, and deliberately not automated. A handler asks for this by
    #: returning a plan with no intended actions — used where acting
    #: automatically is more likely to cause an outage than the finding is
    #: (root credentials, for one).
    ESCALATED = "ESCALATED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Principal:
    """Who made the call, as far as the event tells us."""

    arn: str
    type: str
    name: str
    account_id: str

    @property
    def is_root(self) -> bool:
        return self.type == "Root" or self.arn.endswith(":root")

    def is_pac_automation(self, prefix: str = "pac-") -> bool:
        """True when the caller is this system's own remediation role.

        Without this check a remediation that calls ``PutBucketAcl`` re-triggers
        its own detection, which is a self-sustaining invocation loop with a
        bill attached.
        """
        return prefix in self.arn or self.name.startswith(prefix)


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """A CloudTrail or GuardDuty event normalised to the fields we act on."""

    event_id: str
    event_time: str
    source: str
    account_id: str
    region: str
    principal: Principal
    source_ip: str
    user_agent: str
    detail: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Plan:
    """What the handler intends to do, and the evidence it based that on.

    ``snapshot`` is the pre-change state of the resource. It is written to the
    audit table before anything is modified — that ordering is the whole reason
    this type exists separately from the apply step.
    """

    resource_id: str
    resource_arn: str
    reason: str
    severity: Severity
    snapshot: Mapping[str, Any]
    tags: Mapping[str, str] = field(default_factory=dict)
    blast_radius: Mapping[str, Any] = field(default_factory=dict)
    intended_actions: Sequence[str] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Outcome:
    """Result of one invocation, for the audit record and the alert."""

    detection_id: str
    status: Status
    severity: Severity
    resource_id: str
    reason: str
    actions: Sequence[str] = field(default_factory=tuple)
    error: str | None = None

    @property
    def changed_anything(self) -> bool:
        return self.status is Status.APPLIED
