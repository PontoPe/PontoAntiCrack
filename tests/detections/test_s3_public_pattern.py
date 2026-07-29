"""`s3-public` — what the EventBridge pattern does and does not deliver."""

from __future__ import annotations

import pytest

from tests.conftest import load_event, load_pattern
from tests.support.eventbridge import matches

PATTERN = load_pattern("s3-public")


@pytest.mark.parametrize(
    "fixture",
    [
        "put-bucket-acl-public-read",
        "put-bucket-policy-wildcard-principal",
        "delete-public-access-block",
    ],
)
def test_pattern_matches_bucket_exposure_events(fixture: str) -> None:
    assert matches(PATTERN, load_event("cloudtrail", "s3-public", fixture))


def test_pattern_ignores_read_only_calls() -> None:
    """A false positive here would invoke the Lambda on every permissions-tab
    page load in the console."""
    assert not matches(PATTERN, load_event("cloudtrail", "s3-public", "benign-get-bucket-acl"))


def test_pattern_ignores_failed_calls() -> None:
    """AccessDenied means IAM already stopped it and the bucket never changed."""
    event = load_event("cloudtrail", "s3-public", "benign-put-bucket-acl-access-denied")
    assert event["detail"]["errorCode"] == "AccessDenied"
    assert not matches(PATTERN, event)


def test_pattern_ignores_other_services() -> None:
    event = load_event("cloudtrail", "s3-public", "put-bucket-acl-public-read")
    event["source"] = "aws.ec2"
    event["detail"]["eventSource"] = "ec2.amazonaws.com"
    assert not matches(PATTERN, event)


def test_pattern_watches_exactly_the_four_mutating_apis() -> None:
    """Locks the list down. Adding a fifth event name is a deliberate change
    that has to come with a fixture."""
    assert set(PATTERN["detail"]["eventName"]) == {
        "PutBucketAcl",
        "PutBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
    }
