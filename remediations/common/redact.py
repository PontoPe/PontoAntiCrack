"""Strip credential material before anything leaves the function.

Two rules, applied to every structure written to the audit table or sent to
Slack:

1. **Key-name based.** A value is dropped if its key names a credential
   (``secretAccessKey``, ``sessionToken``, ``password``, ``authorization``…).
   This is the reliable half — it does not depend on guessing what a secret
   looks like.
2. **Value based, narrow.** Only shapes that are unambiguously secret are
   matched: Slack webhook URLs and Slack tokens.

Access key *IDs* (``AKIA…``) are deliberately **not** redacted. They are
identifiers, not secrets, and the `iam-key-leak` alert is useless without the
key it is telling you to go look at.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

PLACEHOLDER = "[redacted]"

_SENSITIVE_KEY_PARTS = (
    "secretaccesskey",
    "sessiontoken",
    "securitytoken",
    "password",
    "passwd",
    "authorization",
    "webhook",
    "privatekey",
    "clientsecret",
    "apikey",
    "api_key",
    "credentials",
)

_SENSITIVE_VALUES = re.compile(
    r"""(
        https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+
      | xox[baprs]-[A-Za-z0-9-]{10,}
    )""",
    re.VERBOSE,
)

_MAX_STRING = 2048


def _key_is_sensitive(key: str) -> bool:
    normalised = key.replace("-", "").replace("_", "").lower()
    return any(part.replace("_", "") in normalised for part in _SENSITIVE_KEY_PARTS)


def scrub_text(value: str) -> str:
    cleaned = _SENSITIVE_VALUES.sub(PLACEHOLDER, value)
    if len(cleaned) > _MAX_STRING:
        cleaned = cleaned[:_MAX_STRING] + "…[truncated]"
    return cleaned


def scrub_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """:func:`scrub` for the common case where the input is known to be a dict."""
    return {
        str(key): (PLACEHOLDER if _key_is_sensitive(str(key)) else scrub(item))
        for key, item in value.items()
    }


def scrub(value: Any) -> Any:
    """Recursively redact ``value``. Returns plain JSON-safe types."""
    if isinstance(value, Mapping):
        return scrub_mapping(value)
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, bytes):
        return PLACEHOLDER
    if isinstance(value, Sequence):
        return [scrub(item) for item in value]
    return value
