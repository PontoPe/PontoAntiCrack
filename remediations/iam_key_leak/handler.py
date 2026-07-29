"""iam-key-leak.

GuardDuty makes the anomaly call; this handler does not try to re-derive it from
raw CloudTrail. What it does is capture what the key was used for *before*
taking it away, then deactivate it.

Two hard rules:

* The key is set to ``Inactive``. It is never deleted. ``GetAccessKeyLastUsed``
  disappears with the key, and in a credential-abuse investigation that record
  is frequently the only evidence of what the attacker actually reached.
* Root credentials are never touched automatically. An automation role that can
  disable root is a bigger problem than the finding, and a wrong call locks the
  account owner out. The finding escalates to a human instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from remediations.common.aws import AwsClients
from remediations.common.detection import Detection
from remediations.common.entrypoint import build
from remediations.common.models import DetectionEvent, Plan, Severity


class IamKeyLeak(Detection):
    id: ClassVar[str] = "iam-key-leak"
    default_severity: ClassVar[Severity] = Severity.CRITICAL

    def plan(self, event: DetectionEvent, aws: AwsClients) -> Plan | None:
        resource = _mapping(event.detail.get("resource"))
        key_details = _mapping(resource.get("accessKeyDetails"))
        access_key_id = str(key_details.get("accessKeyId") or "").strip()
        if not access_key_id:
            return None

        user_name = str(key_details.get("userName") or "").strip()
        user_type = str(key_details.get("userType") or "").strip()
        finding_type = str(event.detail.get("type") or "unknown")
        finding_severity = event.detail.get("severity")

        last_used = _last_used(aws, access_key_id)
        blast_radius = {
            "finding": finding_type,
            "guardduty_severity": finding_severity,
            "last_used_service": last_used.get("ServiceName", "unknown"),
            "last_used_region": last_used.get("Region", "unknown"),
            "last_used_at": str(last_used.get("LastUsedDate", "never")),
            "source_ip": event.source_ip,
        }

        # Only a long-lived IAM user key can be deactivated. Everything else is
        # escalate-only: an empty intended-action list tells the runtime to
        # snapshot, alert critically, and change nothing.
        if user_type != "IAMUser" or not user_name:
            return Plan(
                resource_id=access_key_id,
                resource_arn=_principal_arn(event.account_id, user_type, user_name),
                reason=_escalation_reason(finding_type, access_key_id, user_type, user_name),
                severity=Severity.CRITICAL,
                snapshot={
                    "access_key_id": access_key_id,
                    "user_type": user_type,
                    "user_name": user_name,
                    "access_key_last_used": last_used,
                    "guardduty_finding": {"type": finding_type, "severity": finding_severity},
                },
                tags={},
                blast_radius=blast_radius,
                intended_actions=(),
            )

        key_metadata = _key_metadata(aws, user_name, access_key_id)
        if key_metadata.get("Status") == "Inactive":
            # Already inactive: nothing to do, and re-deactivating would put a
            # misleading APPLIED record in the audit table.
            return None

        tags = _user_tags(aws, user_name)

        return Plan(
            resource_id=access_key_id,
            resource_arn=f"arn:aws:iam::{event.account_id}:user/{user_name}",
            reason=(
                f"GuardDuty {finding_type} (severity {finding_severity}) on access key "
                f"{access_key_id} belonging to IAM user {user_name}, seen from {event.source_ip}"
            ),
            severity=self.default_severity,
            snapshot={
                "access_key_id": access_key_id,
                "user_name": user_name,
                "user_type": user_type,
                "access_key_metadata": key_metadata,
                "access_key_last_used": last_used,
                "user_tags": dict(tags),
                "guardduty_finding": {"type": finding_type, "severity": finding_severity},
            },
            tags=tags,
            blast_radius={**blast_radius, "user": user_name},
            intended_actions=(f"set access key {access_key_id} of user {user_name} to Inactive",),
        )

    def apply(self, plan: Plan, aws: AwsClients) -> list[str]:
        access_key_id = str(plan.snapshot["access_key_id"])
        user_name = str(plan.snapshot["user_name"])
        aws.iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Inactive")
        return [
            f"deactivated access key {access_key_id} for IAM user {user_name} "
            f"(not deleted — last-used history preserved)"
        ]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _principal_arn(account_id: str, user_type: str, user_name: str) -> str:
    if user_type == "Root" or not user_name:
        return f"arn:aws:iam::{account_id}:root"
    if user_type == "AssumedRole":
        return f"arn:aws:iam::{account_id}:role/{user_name}"
    return f"arn:aws:iam::{account_id}:user/{user_name}"


def _escalation_reason(
    finding_type: str, access_key_id: str, user_type: str, user_name: str
) -> str:
    head = f"GuardDuty {finding_type} on credential {access_key_id}"
    if user_type == "Root" or not user_name:
        return (
            f"{head}, which belongs to the account root "
            f"({user_type or 'unidentified principal'}). Root credentials are never "
            f"deactivated automatically — rotate them by hand now."
        )
    if user_type == "AssumedRole":
        return (
            f"{head}, a temporary session credential for role {user_name}. Temporary "
            f"credentials cannot be deactivated; revoke them by attaching an "
            f"AWSRevokeOlderSessions deny-by-date policy to the role, and find out how the "
            f"role was assumed."
        )
    return (
        f"{head}, held by principal type {user_type!r}, which this remediation does not "
        f"know how to act on safely. Handle manually."
    )


def _last_used(aws: AwsClients, access_key_id: str) -> dict[str, Any]:
    try:
        response = aws.iam.get_access_key_last_used(AccessKeyId=access_key_id)
    except Exception:  # noqa: BLE001 - forensic context is best effort
        return {}
    info = response.get("AccessKeyLastUsed", {})
    return dict(info) if isinstance(info, Mapping) else {}


def _key_metadata(aws: AwsClients, user_name: str, access_key_id: str) -> dict[str, Any]:
    response = aws.iam.list_access_keys(UserName=user_name)
    for entry in response.get("AccessKeyMetadata", []) or []:
        if isinstance(entry, Mapping) and entry.get("AccessKeyId") == access_key_id:
            return dict(entry)
    return {}


def _user_tags(aws: AwsClients, user_name: str) -> dict[str, str]:
    try:
        response = aws.iam.list_user_tags(UserName=user_name)
    except Exception:  # noqa: BLE001 - a user with no tags must not block remediation
        return {}
    return {
        str(tag["Key"]): str(tag.get("Value", ""))
        for tag in response.get("Tags", []) or []
        if isinstance(tag, Mapping) and "Key" in tag
    }


lambda_handler = build(IamKeyLeak())
