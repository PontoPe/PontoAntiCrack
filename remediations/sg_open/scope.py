"""Fail-closed lab entrypoint. The unscoped SgOpen class is for offline tests only.

Tags do not establish account isolation. Verify STS, event account/region, SG
owner, exact ID, round tag, name prefix, exclusion and lack of ENIs. IAM also
limits revoke to the exact SG and tag. ENI attachment can race the read: this
is a dedicated lab resource, not a guarantee of EC2 transaction isolation.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from remediations.common.aws import AwsClients
from remediations.common.entrypoint import build
from remediations.common.models import DetectionEvent, Plan
from remediations.sg_open.handler import SgOpen


class ScopeError(RuntimeError):
    """Explicit refusal; no mutation is authorized."""


@dataclass(frozen=True)
class Scope:
    account_id: str
    region: str
    group_id: str
    round_id: str

    @classmethod
    def from_env(cls) -> Scope:
        scope = cls(
            *(
                os.environ.get(key, "")
                for key in (
                    "PAC_SCOPE_ACCOUNT",
                    "PAC_SCOPE_REGION",
                    "PAC_SCOPE_GROUP",
                    "PAC_SCOPE_ROUND",
                )
            )
        )
        if (
            not re.fullmatch(r"\d{12}", scope.account_id)
            or scope.region != "sa-east-1"
            or not re.fullmatch(r"sg-[a-f0-9]+", scope.group_id)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", scope.round_id)
        ):
            raise ScopeError("missing or invalid explicit lab scope")
        return scope

    def verify_identity(self, aws: AwsClients) -> None:
        if (
            aws.client("sts").get_caller_identity()["Account"] != self.account_id
            or aws.ec2.meta.region_name != self.region
        ):
            raise ScopeError("caller account/region differs from scope")

    def inspect(self, aws: AwsClients, group_id: str) -> Mapping[str, Any]:
        self.verify_identity(aws)
        if group_id != self.group_id:
            raise ScopeError("group ID differs from scope")
        group: Mapping[str, Any] = aws.ec2.describe_security_groups(GroupIds=[group_id])[
            "SecurityGroups"
        ][0]
        tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
        if (
            group.get("OwnerId") != self.account_id
            or not str(group.get("GroupName", "")).startswith("pac-")
            or tags.get("pac:canary") != self.round_id
            or "pac:exclude" in tags
        ):
            raise ScopeError("group owner/name/tags are not eligible")
        # MaxResults is intentionally absent: EC2 returns all matching ENIs,
        # and even one (or a pagination token) must refuse mutation.
        interfaces = aws.ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [group_id]}]
        )
        if interfaces.get("NetworkInterfaces") or interfaces.get("NextToken"):
            raise ScopeError("group has attached interfaces or incomplete inventory")
        return group


class GuardedSgOpen(SgOpen):
    def __init__(self, scope: Scope | None = None) -> None:
        self._scope = scope

    @property
    def scope(self) -> Scope:
        return self._scope if self._scope is not None else Scope.from_env()

    def plan(self, event: DetectionEvent, aws: AwsClients) -> Plan | None:
        if event.account_id != self.scope.account_id or event.region != self.scope.region:
            raise ScopeError("event account/region differs from scope")
        group_id = str(event.detail.get("requestParameters", {}).get("groupId", ""))
        self.scope.inspect(aws, group_id)
        return super().plan(event, aws)

    def apply(self, plan: Plan, aws: AwsClients) -> list[str]:
        self.scope.inspect(aws, plan.resource_id)
        return super().apply(plan, aws)


lambda_handler = build(GuardedSgOpen())
