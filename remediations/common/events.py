"""Normalise the two event shapes this system consumes.

Events are untrusted input. Everything below reads defensively: a missing key is
an unknown value, never an exception, because a handler that crashes on an
unexpected CloudTrail shape is a detection that silently stopped working.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from remediations.common.models import DetectionEvent, Principal

UNKNOWN = "unknown"


class UnsupportedEventError(ValueError):
    """The event is not one this system knows how to read."""


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, default: str = UNKNOWN) -> str:
    if isinstance(value, str) and value:
        return value
    return default


def parse(event: Mapping[str, Any]) -> DetectionEvent:
    """Turn a raw EventBridge envelope into a :class:`DetectionEvent`."""
    source = _text(event.get("source"))
    detail = _mapping(event.get("detail"))

    if source == "aws.guardduty":
        return _parse_guardduty(event, detail)
    if _text(event.get("detail-type")) == "AWS API Call via CloudTrail":
        return _parse_cloudtrail(event, detail)
    raise UnsupportedEventError(f"unsupported event source {source!r}")


def _parse_cloudtrail(event: Mapping[str, Any], detail: Mapping[str, Any]) -> DetectionEvent:
    identity = _mapping(detail.get("userIdentity"))
    session_issuer = _mapping(_mapping(identity.get("sessionContext")).get("sessionIssuer"))

    # For an assumed role the useful name is the role, not the ephemeral session.
    name = _text(identity.get("userName"), default="")
    if not name:
        name = _text(session_issuer.get("userName"), default="")
    if not name:
        name = _text(identity.get("principalId"), default=UNKNOWN).split(":", 1)[0]

    principal = Principal(
        arn=_text(identity.get("arn")),
        type=_text(identity.get("type")),
        name=name or UNKNOWN,
        account_id=_text(identity.get("accountId"), default=_text(event.get("account"))),
    )

    return DetectionEvent(
        event_id=_text(detail.get("eventID"), default=_text(event.get("id"))),
        event_time=_text(detail.get("eventTime"), default=_text(event.get("time"))),
        source=_text(event.get("source")),
        account_id=_text(event.get("account"), default=_text(detail.get("recipientAccountId"))),
        region=_text(detail.get("awsRegion"), default=_text(event.get("region"))),
        principal=principal,
        source_ip=_text(detail.get("sourceIPAddress")),
        user_agent=_text(detail.get("userAgent")),
        detail=detail,
    )


def _parse_guardduty(event: Mapping[str, Any], detail: Mapping[str, Any]) -> DetectionEvent:
    resource = _mapping(detail.get("resource"))
    key_details = _mapping(resource.get("accessKeyDetails"))
    remote = _mapping(
        _mapping(
            _mapping(_mapping(detail.get("service")).get("action")).get("awsApiCallAction")
        ).get("remoteIpDetails")
    )

    principal = Principal(
        arn=_text(key_details.get("principalId")),
        type=_text(key_details.get("userType")),
        name=_text(key_details.get("userName")),
        account_id=_text(detail.get("accountId"), default=_text(event.get("account"))),
    )

    return DetectionEvent(
        event_id=_text(detail.get("id"), default=_text(event.get("id"))),
        event_time=_text(
            _mapping(detail.get("service")).get("eventLastSeen"), default=_text(event.get("time"))
        ),
        source=_text(event.get("source")),
        account_id=_text(detail.get("accountId"), default=_text(event.get("account"))),
        region=_text(detail.get("region"), default=_text(event.get("region"))),
        principal=principal,
        source_ip=_text(remote.get("ipAddressV4")),
        user_agent=UNKNOWN,
        detail=detail,
    )


def request_parameters(event: DetectionEvent) -> Mapping[str, Any]:
    """CloudTrail ``requestParameters``, or an empty mapping."""
    return _mapping(event.detail.get("requestParameters"))


def as_items(value: Any) -> list[Any]:
    """Flatten CloudTrail's two list encodings into a plain list.

    CloudTrail renders EC2 lists as ``{"items": [...]}`` and most other services
    as a bare list. Both appear in the wild depending on the API, so callers get
    one shape.
    """
    if isinstance(value, Mapping):
        inner = value.get("items")
        return list(inner) if isinstance(inner, list) else []
    if isinstance(value, list):
        return list(value)
    return []
