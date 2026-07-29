"""Shared test fixtures.

No test in this tree talks to AWS. `moto` stands in for every service, and the
credentials below are deliberately obvious fakes so that a misconfigured `moto`
fails with an auth error instead of silently reaching a real account.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

from remediations.common.aws import AwsClients
from remediations.common.config import Config

REGION = "sa-east-1"
ACCOUNT_ID = "111111111111"
TABLE_NAME = "pac-audit-test"

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures"
DETECTION_ROOT = REPO_ROOT / "detections"


@pytest.fixture(autouse=True)
def _fake_credentials() -> Iterator[None]:
    original = dict(os.environ)
    os.environ.update(
        {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SECURITY_TOKEN": "testing",
            "AWS_SESSION_TOKEN": "testing",
            "AWS_DEFAULT_REGION": REGION,
            "AWS_REGION": REGION,
        }
    )
    yield
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def aws(_fake_credentials: None) -> Iterator[AwsClients]:
    with mock_aws():
        yield AwsClients(region_name=REGION)


@pytest.fixture
def audit_table(aws: AwsClients) -> Any:
    client = aws.client("dynamodb")
    client.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return aws.table(TABLE_NAME)


def make_config(**overrides: Any) -> Config:
    """A Config with test defaults. ``dry_run`` is False so handlers act."""
    base: dict[str, Any] = {
        "detection_id": "test-detection",
        "table_name": TABLE_NAME,
        "environment": "test",
        "dry_run": False,
        "exclusion_tag": "pac:exclude",
        "circuit_breaker_max_actions": 5,
        "circuit_breaker_window_seconds": 300,
        "dedup_window_seconds": 900,
        "slack_secret_arn": None,
    }
    base.update(overrides)
    return Config(**base)


@pytest.fixture
def config_factory() -> Any:
    return make_config


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_event(category: str, detection: str, name: str) -> dict[str, Any]:
    """Load a fixture event by ``category/detection/name``."""
    return load_json(FIXTURE_ROOT / category / detection / f"{name}.json")


def load_pattern(detection: str) -> dict[str, Any]:
    return load_json(DETECTION_ROOT / detection / "pattern.json")


def fixture_files(category: str, detection: str) -> list[Path]:
    return sorted((FIXTURE_ROOT / category / detection).glob("*.json"))


class RecordingNotifier:
    """Captures alerts instead of sending them."""

    def __init__(self) -> None:
        self.sent: list[tuple[Any, Any, Any]] = []

    def notify(self, event: Any, outcome: Any, plan: Any) -> bool:
        self.sent.append((event, outcome, plan))
        return True

    @property
    def statuses(self) -> list[str]:
        return [outcome.status.value for _, outcome, _ in self.sent]


@pytest.fixture
def notifier() -> RecordingNotifier:
    return RecordingNotifier()


def seed_bucket(
    aws: AwsClients,
    bucket: str,
    *,
    acl: str | None = None,
    policy: Mapping[str, Any] | None = None,
    public_access_block: Mapping[str, bool] | None = None,
    tags: Mapping[str, str] | None = None,
) -> None:
    """Create a bucket in moto with the exposure state a test needs."""
    aws.s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": REGION},
        ObjectOwnership="BucketOwnerPreferred",
    )
    if acl is not None:
        aws.s3.put_bucket_acl(Bucket=bucket, ACL=acl)
    if policy is not None:
        aws.s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    if public_access_block is not None:
        aws.s3.put_public_access_block(
            Bucket=bucket, PublicAccessBlockConfiguration=dict(public_access_block)
        )
    if tags:
        aws.s3.put_bucket_tagging(
            Bucket=bucket,
            Tagging={"TagSet": [{"Key": key, "Value": value} for key, value in tags.items()]},
        )


def seed_security_group(
    aws: AwsClients,
    *,
    permissions: list[dict[str, Any]],
    tags: Mapping[str, str] | None = None,
) -> str:
    """Create a VPC security group in moto with ``permissions`` authorised."""
    vpc = aws.ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    group = aws.ec2.create_security_group(
        GroupName="pac-test-sg", Description="pac test", VpcId=vpc["VpcId"]
    )
    group_id: str = group["GroupId"]
    if permissions:
        aws.ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    if tags:
        aws.ec2.create_tags(
            Resources=[group_id],
            Tags=[{"Key": key, "Value": value} for key, value in tags.items()],
        )
    return group_id


def seed_iam_user(aws: AwsClients, user_name: str, *, tags: Mapping[str, str] | None = None) -> str:
    """Create an IAM user with one active access key. Returns the key ID."""
    kwargs: dict[str, Any] = {"UserName": user_name}
    if tags:
        kwargs["Tags"] = [{"Key": key, "Value": value} for key, value in tags.items()]
    aws.iam.create_user(**kwargs)
    key = aws.iam.create_access_key(UserName=user_name)["AccessKey"]
    return str(key["AccessKeyId"])


__all__ = [
    "ACCOUNT_ID",
    "REGION",
    "TABLE_NAME",
    "RecordingNotifier",
    "boto3",
    "fixture_files",
    "load_event",
    "load_json",
    "load_pattern",
    "make_config",
    "seed_bucket",
    "seed_iam_user",
    "seed_security_group",
]
