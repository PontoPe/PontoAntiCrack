"""Keep detection IAM allows aligned with the SDK calls in each handler."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]

DETECTIONS = (
    ("iam_key_leak", "iam"),
    ("s3_public", "s3"),
    ("sg_open", "ec2"),
)

ACTION_NAME_OVERRIDES = {
    ("s3", "get_public_access_block"): "GetBucketPublicAccessBlock",
    ("s3", "put_public_access_block"): "PutBucketPublicAccessBlock",
}


def _policy_allow_actions(policy_path: Path) -> set[str]:
    policy: dict[str, Any] = json.loads(policy_path.read_text(encoding="utf-8"))
    actions: set[str] = set()

    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow":
            continue

        value = statement["Action"]
        actions.update([value] if isinstance(value, str) else value)

    return actions


def _handler_client_calls(handler_path: Path) -> set[tuple[str, str]]:
    tree = ast.parse(handler_path.read_text(encoding="utf-8"), filename=str(handler_path))
    calls: set[tuple[str, str]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue

        client = node.func.value
        if (
            isinstance(client, ast.Attribute)
            and isinstance(client.value, ast.Name)
            and client.value.id == "aws"
        ):
            calls.add((client.attr, node.func.attr))

    return calls


def _iam_action(service: str, method: str) -> str:
    # TODO: Add an explicit override here when an SDK operation name differs
    # from its IAM action instead of weakening this exact-match gate.
    action_name = ACTION_NAME_OVERRIDES.get(
        (service, method),
        "".join(part.capitalize() for part in method.split("_")),
    )
    return f"{service}:{action_name}"


@pytest.mark.parametrize(("package", "service"), DETECTIONS)
def test_detection_policy_allows_exactly_the_handler_calls(package: str, service: str) -> None:
    remediation = ROOT / "remediations" / package
    allowed = _policy_allow_actions(remediation / "policy.json")
    calls = _handler_client_calls(remediation / "handler.py")
    used = {_iam_action(call_service, method) for call_service, method in calls}

    assert {call_service for call_service, _ in calls} == {service}
    assert allowed == used
