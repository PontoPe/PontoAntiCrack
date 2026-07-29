"""Tests for the local EventBridge pattern evaluator.

The evaluator is test infrastructure, which is exactly why it needs its own
tests: a bug here turns every detection test green for the wrong reason.
"""

from __future__ import annotations

import pytest

from tests.support.eventbridge import UnsupportedPatternError, matches


def test_exact_value_matches() -> None:
    assert matches({"source": ["aws.s3"]}, {"source": "aws.s3"})


def test_exact_value_rejects_other_value() -> None:
    assert not matches({"source": ["aws.s3"]}, {"source": "aws.ec2"})


def test_missing_key_does_not_match() -> None:
    assert not matches({"source": ["aws.s3"]}, {"detail-type": "x"})


def test_all_top_level_keys_must_match() -> None:
    pattern = {"source": ["aws.s3"], "detail-type": ["AWS API Call via CloudTrail"]}
    assert not matches(pattern, {"source": "aws.s3", "detail-type": "Something Else"})


def test_nested_object_descends() -> None:
    pattern = {"detail": {"eventName": ["PutBucketAcl"]}}
    assert matches(pattern, {"detail": {"eventName": "PutBucketAcl"}})
    assert not matches(pattern, {"detail": {"eventName": "GetBucketAcl"}})


def test_exists_false_matches_only_when_absent() -> None:
    pattern = {"detail": {"errorCode": [{"exists": False}]}}
    assert matches(pattern, {"detail": {"eventName": "x"}})
    assert not matches(pattern, {"detail": {"errorCode": "AccessDenied"}})


def test_exists_true_matches_only_when_present() -> None:
    pattern = {"detail": {"errorCode": [{"exists": True}]}}
    assert matches(pattern, {"detail": {"errorCode": "AccessDenied"}})
    assert not matches(pattern, {"detail": {}})


def test_prefix_matcher() -> None:
    pattern = {"detail": {"type": [{"prefix": "UnauthorizedAccess:IAMUser/"}]}}
    assert matches(pattern, {"detail": {"type": "UnauthorizedAccess:IAMUser/TorIPCaller"}})
    assert not matches(pattern, {"detail": {"type": "Discovery:IAMUser/AnomalousBehavior"}})


@pytest.mark.parametrize(
    ("severity", "expected"),
    [(2, False), (3.9, False), (4, True), (5, True), (8, True)],
)
def test_numeric_matcher(severity: float, expected: bool) -> None:
    pattern = {"detail": {"severity": [{"numeric": [">=", 4]}]}}
    assert matches(pattern, {"detail": {"severity": severity}}) is expected


def test_numeric_matcher_rejects_non_numbers() -> None:
    pattern = {"detail": {"severity": [{"numeric": [">=", 4]}]}}
    assert not matches(pattern, {"detail": {"severity": "high"}})


def test_anything_but() -> None:
    pattern = {"detail": {"eventName": [{"anything-but": ["GetBucketAcl"]}]}}
    assert matches(pattern, {"detail": {"eventName": "PutBucketAcl"}})
    assert not matches(pattern, {"detail": {"eventName": "GetBucketAcl"}})


def test_matches_into_array_of_objects() -> None:
    """The behaviour the sg-open pattern depends on entirely."""
    pattern = {"detail": {"ipPermissions": {"items": {"cidrIp": ["0.0.0.0/0"]}}}}
    event = {
        "detail": {"ipPermissions": {"items": [{"cidrIp": "10.0.0.0/8"}, {"cidrIp": "0.0.0.0/0"}]}}
    }
    assert matches(pattern, event)


def test_array_match_requires_at_least_one_element_to_match() -> None:
    pattern = {"detail": {"ipPermissions": {"items": {"cidrIp": ["0.0.0.0/0"]}}}}
    event = {"detail": {"ipPermissions": {"items": [{"cidrIp": "10.0.0.0/8"}]}}}
    assert not matches(pattern, event)


def test_or_matches_when_either_branch_matches() -> None:
    pattern = {
        "source": ["aws.ec2"],
        "$or": [
            {"detail": {"a": ["yes"]}},
            {"detail": {"b": ["yes"]}},
        ],
    }
    assert matches(pattern, {"source": "aws.ec2", "detail": {"b": "yes"}})
    assert matches(pattern, {"source": "aws.ec2", "detail": {"a": "yes"}})
    assert not matches(pattern, {"source": "aws.ec2", "detail": {"c": "yes"}})


def test_or_is_still_anded_with_its_siblings() -> None:
    pattern = {"source": ["aws.ec2"], "$or": [{"detail": {"a": ["yes"]}}]}
    assert not matches(pattern, {"source": "aws.s3", "detail": {"a": "yes"}})


def test_unknown_matcher_raises_rather_than_guessing() -> None:
    with pytest.raises(UnsupportedPatternError):
        matches({"detail": {"x": [{"cidr": "10.0.0.0/8"}]}}, {"detail": {"x": "10.0.0.1"}})


def test_scalar_pattern_value_is_rejected() -> None:
    """EventBridge requires a list at a leaf; accepting a bare scalar here would
    let a malformed pattern pass its own test."""
    with pytest.raises(UnsupportedPatternError):
        matches({"source": "aws.s3"}, {"source": "aws.s3"})
