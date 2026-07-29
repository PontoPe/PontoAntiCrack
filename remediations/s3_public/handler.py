"""s3-public.

The EventBridge pattern is deliberately coarse — it fires on any of the four
APIs that *can* make a bucket public, because whether the resulting state is
public is not decidable from the event alone. This handler makes that call by
reading the bucket back.

Remediation is Block Public Access plus, if the ACL is what went public, an ACL
reset. The bucket policy is never deleted: BPA already neutralises a public
policy, and the policy is both the operator's intent and evidence of what the
attacker granted themselves.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, ClassVar

from remediations.common import events as event_parser
from remediations.common.aws import AwsClients
from remediations.common.detection import Detection
from remediations.common.entrypoint import build
from remediations.common.models import DetectionEvent, Plan, Severity

PUBLIC_ACL_URIS = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)

FULL_BLOCK_PUBLIC_ACCESS = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class S3Public(Detection):
    id: ClassVar[str] = "s3-public"
    default_severity: ClassVar[Severity] = Severity.HIGH

    def plan(self, event: DetectionEvent, aws: AwsClients) -> Plan | None:
        bucket = str(event_parser.request_parameters(event).get("bucketName") or "").strip()
        if not bucket:
            return None

        acl = _safe(lambda: aws.s3.get_bucket_acl(Bucket=bucket), default={})
        policy_document = _load_policy(aws, bucket)
        block = _safe(
            lambda: aws.s3.get_public_access_block(Bucket=bucket).get(
                "PublicAccessBlockConfiguration", {}
            ),
            default={},
        )
        tags = _load_tags(aws, bucket)

        public_grants = _public_acl_grants(acl)
        policy_is_public = _policy_is_public(policy_document)
        block_is_complete = all(block.get(key) is True for key in FULL_BLOCK_PUBLIC_ACCESS)

        reasons: list[str] = []
        if public_grants:
            reasons.append(f"ACL grants {', '.join(sorted(public_grants))}")
        if policy_is_public:
            reasons.append("bucket policy allows Principal '*' with no restricting condition")

        # An incomplete Block Public Access config is only a finding when
        # something is actually public through it. Reporting every bucket
        # without BPA would drown the real exposures — that is a posture check
        # for Config, not a detection.
        if not reasons:
            return None
        if block_is_complete:
            # Public grants exist but BPA already neutralises them. Worth
            # recording, not worth changing anything for.
            return None

        intended: list[str] = ["enable all four Block Public Access settings"]
        if public_grants:
            intended.append("reset bucket ACL to private")

        return Plan(
            resource_id=bucket,
            resource_arn=f"arn:aws:s3:::{bucket}",
            reason="; ".join(reasons),
            severity=self.default_severity,
            snapshot={
                "bucket": bucket,
                "acl": acl,
                "bucket_policy": policy_document,
                "public_access_block": block,
                "tags": dict(tags),
                "triggering_event_name": event.detail.get("eventName"),
            },
            tags=tags,
            blast_radius={
                "public_via": ",".join(
                    filter(
                        None,
                        [
                            "acl" if public_grants else "",
                            "policy" if policy_is_public else "",
                        ],
                    )
                ),
                "block_public_access": "partial" if block else "absent",
                "region": event.region,
            },
            intended_actions=tuple(intended),
        )

    def apply(self, plan: Plan, aws: AwsClients) -> list[str]:
        bucket = plan.resource_id
        actions: list[str] = []

        aws.s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration=dict(FULL_BLOCK_PUBLIC_ACCESS),
        )
        actions.append(f"enabled Block Public Access on s3://{bucket}")

        acl = plan.snapshot.get("acl", {})
        if _public_acl_grants(acl):
            aws.s3.put_bucket_acl(Bucket=bucket, ACL="private")
            actions.append(f"reset ACL to private on s3://{bucket}")

        if _policy_is_public(plan.snapshot.get("bucket_policy")):
            actions.append(
                "bucket policy left in place — Block Public Access neutralises it and the "
                "policy is retained as evidence"
            )
        return actions


def _public_acl_grants(acl: Any) -> set[str]:
    if not isinstance(acl, Mapping):
        return set()
    found: set[str] = set()
    for grant in acl.get("Grants", []) or []:
        if not isinstance(grant, Mapping):
            continue
        grantee = grant.get("Grantee")
        if isinstance(grantee, Mapping) and grantee.get("URI") in PUBLIC_ACL_URIS:
            found.add(f"{grantee['URI'].rsplit('/', 1)[-1]}:{grant.get('Permission', 'UNKNOWN')}")
    return found


def _policy_is_public(document: Any) -> bool:
    """Conservative: a statement with a Condition is not treated as public.

    Getting this wrong in the permissive direction means auto-remediating a
    bucket that was fine — which is threat R2 with extra steps. A policy that is
    genuinely public *and* conditioned is rare; a policy that is safe because of
    its condition (``aws:PrincipalOrgID``, a VPC endpoint, an IP allow-list) is
    routine.
    """
    if not isinstance(document, Mapping):
        return False
    statements = document.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False

    for statement in statements:
        if not isinstance(statement, Mapping):
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        if _principal_is_wildcard(statement.get("Principal")):
            return True
    return False


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, Mapping):
        aws_principal = principal.get("AWS")
        if aws_principal == "*":
            return True
        if isinstance(aws_principal, list) and "*" in aws_principal:
            return True
    return False


def _load_policy(aws: AwsClients, bucket: str) -> dict[str, Any] | None:
    raw = _safe(lambda: aws.s3.get_bucket_policy(Bucket=bucket).get("Policy"), default=None)
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _load_tags(aws: AwsClients, bucket: str) -> dict[str, str]:
    tag_set = _safe(lambda: aws.s3.get_bucket_tagging(Bucket=bucket).get("TagSet", []), default=[])
    if not isinstance(tag_set, list):
        return {}
    return {
        str(tag["Key"]): str(tag.get("Value", ""))
        for tag in tag_set
        if isinstance(tag, Mapping) and "Key" in tag
    }


#: Error codes that mean "the bucket has none of that configured", which is a
#: normal state and one we specifically need to reason about. Anything else —
#: AccessDenied above all — is a real failure and must surface as a FAILED
#: outcome with a critical alert. Swallowing AccessDenied here would turn an
#: under-scoped execution role into a detection that quietly reports every
#: bucket as safe.
_ABSENT_CONFIG_CODES = frozenset(
    {
        "NoSuchBucketPolicy",
        "NoSuchTagSet",
        "NoSuchPublicAccessBlockConfiguration",
        "NoSuchConfiguration",
        "ServerSideEncryptionConfigurationNotFoundError",
    }
)


def _safe(call: Any, default: Any) -> Any:
    try:
        return call()
    except Exception as exc:  # noqa: BLE001 - botocore raises dynamically generated classes
        code = _error_code(exc)
        if code in _ABSENT_CONFIG_CODES:
            return default
        raise


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            return str(error.get("Code", ""))
    return type(exc).__name__


lambda_handler = build(S3Public())
