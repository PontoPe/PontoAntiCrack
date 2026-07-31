"""`sg-open` — what the EventBridge pattern does and does not deliver."""

from __future__ import annotations

import pytest

from tests.conftest import load_event, load_pattern
from tests.support.eventbridge import matches

PATTERN = load_pattern("sg-open")


@pytest.mark.parametrize(
    "fixture",
    [
        "authorize-ingress-ssh-world",
        "authorize-ingress-rdp-world-ipv6",
        "authorize-ingress-ssh-world-legacy-params",
    ],
)
def test_pattern_matches_world_open_ingress(fixture: str) -> None:
    assert matches(PATTERN, load_event("cloudtrail", "sg-open", fixture))


def test_pattern_matches_the_legacy_parameter_encoding() -> None:
    """AuthorizeSecurityGroupIngress has two CloudTrail encodings for the same
    call, and the pattern originally knew one of them.

    The AWS CLI sends `IpPermissions` and CloudTrail records the nested
    `ipPermissions.items[].ipRanges.items[].cidrIp`. A caller using the legacy
    top-level parameters — which is what the SDK path Stratus Red Team uses
    does — produces an empty `ipPermissions` and `ipProtocol`/`fromPort`/
    `toPort`/`cidrIp` directly on `requestParameters`.

    This was found by detonating the technique: port 22 was opened to the
    internet and the rule did not match, while the Terraform warm-up's own
    443 rule did. Every unit test passed throughout, because every fixture had
    been produced by the CLI."""
    event = load_event("cloudtrail", "sg-open", "authorize-ingress-ssh-world-legacy-params")
    params = event["detail"]["requestParameters"]

    assert params["ipPermissions"] == {}, "fixture is not the legacy encoding"
    assert params["cidrIp"] == "0.0.0.0/0"
    assert matches(PATTERN, event)


def test_pattern_ignores_internal_cidr_in_the_legacy_encoding() -> None:
    event = load_event(
        "cloudtrail", "sg-open", "benign-authorize-ingress-legacy-params-internal-cidr"
    )
    assert not matches(PATTERN, event)


def test_pattern_ignores_internal_cidr() -> None:
    """The load-bearing negative. SSH from 10.0.0.0/8 is the most common
    legitimate security group change there is; matching it would drown the
    detection in routine traffic."""
    event = load_event("cloudtrail", "sg-open", "benign-authorize-ingress-internal-cidr")
    assert not matches(PATTERN, event)


def test_pattern_ignores_failed_authorize() -> None:
    event = load_event("cloudtrail", "sg-open", "benign-authorize-ingress-failed")
    assert (
        event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["ipRanges"]["items"][0][
            "cidrIp"
        ]
        == "0.0.0.0/0"
    )
    assert not matches(PATTERN, event), "a failed authorize created no rule to revoke"


def test_pattern_matches_https_because_ports_are_the_handler_s_job() -> None:
    """Not an oversight. EventBridge patterns cannot evaluate a FromPort/ToPort
    range, so 443-to-the-world is delivered and then dropped by the handler —
    see test_sg_open_handler.py."""
    assert matches(PATTERN, load_event("cloudtrail", "sg-open", "authorize-ingress-https-world"))


def test_pattern_matches_mixed_cidr_rule() -> None:
    """A permission entry listing both an internal and a world CIDR must match:
    EventBridge matches if any array element matches."""
    event = load_event("cloudtrail", "sg-open", "authorize-ingress-ssh-world")
    permission = event["detail"]["requestParameters"]["ipPermissions"]["items"][0]
    permission["ipRanges"]["items"] = [{"cidrIp": "10.0.0.0/8"}, {"cidrIp": "0.0.0.0/0"}]
    assert matches(PATTERN, event)


def test_pattern_only_watches_authorize() -> None:
    assert PATTERN["detail"]["eventName"] == ["AuthorizeSecurityGroupIngress"]
