"""`s3-public` handler: does it decide correctly, and does it fix the right thing."""

from __future__ import annotations

import json
from typing import Any

from remediations.common import events as event_parser
from remediations.common.aws import AwsClients
from remediations.s3_public.handler import S3Public
from tests.conftest import load_event, seed_bucket

BUCKET = "pac-lab-demo-assets"
DETECTION = S3Public()

PUBLIC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
        }
    ],
}

ORG_SCOPED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "OrgOnly",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example12345"}},
        }
    ],
}

FULLY_BLOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _event(fixture: str = "put-bucket-acl-public-read") -> Any:
    return event_parser.parse(load_event("cloudtrail", "s3-public", fixture))


def test_public_acl_produces_a_plan(aws: AwsClients) -> None:
    seed_bucket(aws, BUCKET, acl="public-read")

    plan = DETECTION.plan(_event(), aws)

    assert plan is not None
    assert plan.resource_id == BUCKET
    assert "ACL grants" in plan.reason
    assert "enable all four Block Public Access settings" in plan.intended_actions
    assert "reset bucket ACL to private" in plan.intended_actions


def test_public_policy_produces_a_plan(aws: AwsClients) -> None:
    seed_bucket(aws, BUCKET, policy=PUBLIC_POLICY)

    plan = DETECTION.plan(_event("put-bucket-policy-wildcard-principal"), aws)

    assert plan is not None
    assert "Principal '*'" in plan.reason
    # The policy is not in the intended actions: it is neutralised, not deleted.
    assert not any("polic" in action for action in plan.intended_actions)


def test_conditioned_wildcard_policy_is_not_treated_as_public(aws: AwsClients) -> None:
    """The false-positive guard. A wildcard principal scoped by
    aws:PrincipalOrgID is the standard way to share a bucket inside an
    organisation — remediating it would be an outage we caused."""
    seed_bucket(aws, BUCKET, policy=ORG_SCOPED_POLICY)

    assert DETECTION.plan(_event("put-bucket-policy-wildcard-principal"), aws) is None


def test_private_bucket_produces_no_plan(aws: AwsClients) -> None:
    seed_bucket(aws, BUCKET, acl="private")

    assert DETECTION.plan(_event(), aws) is None


def test_public_acl_already_neutralised_by_block_public_access(aws: AwsClients) -> None:
    """Public grants exist but all four BPA settings are on. Nothing is exposed,
    so changing anything would be noise in the audit table."""
    seed_bucket(aws, BUCKET, acl="public-read", public_access_block=FULLY_BLOCKED)

    assert DETECTION.plan(_event(), aws) is None


def test_snapshot_captures_state_before_any_change(aws: AwsClients) -> None:
    seed_bucket(aws, BUCKET, acl="public-read", policy=PUBLIC_POLICY, tags={"env": "lab"})

    plan = DETECTION.plan(_event(), aws)

    assert plan is not None
    assert plan.snapshot["bucket"] == BUCKET
    assert plan.snapshot["acl"]["Grants"], "prior ACL must be recoverable"
    assert plan.snapshot["bucket_policy"] == PUBLIC_POLICY
    assert plan.tags == {"env": "lab"}


def test_apply_enables_block_public_access_and_resets_acl(aws: AwsClients) -> None:
    seed_bucket(aws, BUCKET, acl="public-read")
    plan = DETECTION.plan(_event(), aws)
    assert plan is not None

    actions = DETECTION.apply(plan, aws)

    block = aws.s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
    assert block == FULLY_BLOCKED
    assert not _public_grants(aws)
    assert any("Block Public Access" in action for action in actions)
    assert any("private" in action for action in actions)


def test_apply_never_deletes_the_bucket_policy(aws: AwsClients) -> None:
    """Deleting it would destroy both the operator's intent and the record of
    what the attacker granted themselves."""
    seed_bucket(aws, BUCKET, policy=PUBLIC_POLICY)
    plan = DETECTION.plan(_event("put-bucket-policy-wildcard-principal"), aws)
    assert plan is not None

    actions = DETECTION.apply(plan, aws)

    still_there = json.loads(aws.s3.get_bucket_policy(Bucket=BUCKET)["Policy"])
    assert still_there == PUBLIC_POLICY
    assert any("left in place" in action for action in actions)


def test_missing_bucket_name_is_not_an_error(aws: AwsClients) -> None:
    raw = load_event("cloudtrail", "s3-public", "put-bucket-acl-public-read")
    raw["detail"]["requestParameters"] = {}

    assert DETECTION.plan(event_parser.parse(raw), aws) is None


def test_access_denied_while_inspecting_is_not_swallowed(aws: AwsClients) -> None:
    """A detection that reports every bucket as safe because its own role is
    under-scoped is worse than no detection. The failure has to surface."""
    seed_bucket(aws, BUCKET, acl="public-read")

    class DeniedError(Exception):
        response = {"Error": {"Code": "AccessDenied"}}

    def boom(**_: Any) -> Any:
        raise DeniedError

    aws.s3.get_bucket_acl = boom  # type: ignore[method-assign]

    try:
        DETECTION.plan(_event(), aws)
    except DeniedError:
        return
    raise AssertionError("AccessDenied must propagate, not be treated as 'not public'")


def _public_grants(aws: AwsClients) -> list[dict[str, Any]]:
    grants = aws.s3.get_bucket_acl(Bucket=BUCKET).get("Grants", [])
    return [
        grant
        for grant in grants
        if "AllUsers" in str(grant.get("Grantee", {}).get("URI", ""))
        or "AuthenticatedUsers" in str(grant.get("Grantee", {}).get("URI", ""))
    ]
