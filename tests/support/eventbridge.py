"""A local implementation of the EventBridge event-pattern language.

Why this exists: asserting that a pattern matches a fixture requires evaluating
the pattern, and the authoritative evaluator is `aws events test-event-pattern`,
which is an AWS API call. Unit tests in this repo make no AWS calls, so the
subset of the language the patterns actually use is implemented here.

**This is a reimplementation, and reimplementations drift.** It covers exact
values, `prefix`, `suffix`, `exists`, `equals-ignore-case`, `anything-but`,
`wildcard`, `numeric`, `$or`, and matching into arrays. Anything outside that
raises rather than quietly returning the wrong answer.

The tests it powers prove the pattern says what its author meant. They do not
prove EventBridge agrees. Confirming that needs one
`aws events test-event-pattern` call per pattern against the real service, which
is on the post-deploy checklist in docs/session-report.md.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping, Sequence
from typing import Any

_MISSING = object()

_SUPPORTED_MATCHERS = frozenset(
    {"prefix", "suffix", "exists", "equals-ignore-case", "anything-but", "wildcard", "numeric"}
)


class UnsupportedPatternError(NotImplementedError):
    """The pattern uses a feature this evaluator does not implement."""


def matches(pattern: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    """True if ``event`` would be delivered by a rule using ``pattern``."""
    return _match_object(pattern, event)


def _match_object(pattern: Mapping[str, Any], value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False

    for key, sub in pattern.items():
        if key == "$or":
            if not isinstance(sub, Sequence) or isinstance(sub, str):
                raise UnsupportedPatternError("$or takes a list of patterns")
            if not any(_match_object(branch, value) for branch in sub):
                return False
            continue

        actual = value.get(key, _MISSING)

        if isinstance(sub, Mapping):
            if actual is _MISSING or not _match_nested(sub, actual):
                return False
        elif isinstance(sub, list):
            if not _match_leaf(sub, actual):
                return False
        else:
            raise UnsupportedPatternError(
                f"pattern value for {key!r} must be a list or an object, got {type(sub).__name__}"
            )
    return True


def _match_nested(pattern: Mapping[str, Any], actual: Any) -> bool:
    # EventBridge descends into arrays: a pattern under `ipPermissions` matches
    # if any element of the array matches it.
    if isinstance(actual, list):
        return any(_match_nested(pattern, item) for item in actual)
    return _match_object(pattern, actual)


def _match_leaf(matchers: Sequence[Any], actual: Any) -> bool:
    return any(_match_one(matcher, actual) for matcher in matchers)


def _match_one(matcher: Any, actual: Any) -> bool:
    if isinstance(matcher, Mapping):
        return _match_matcher_object(matcher, actual)
    if actual is _MISSING:
        return False
    if isinstance(actual, list):
        return any(item == matcher for item in actual)
    return bool(actual == matcher)


def _match_matcher_object(matcher: Mapping[str, Any], actual: Any) -> bool:
    if len(matcher) != 1:
        raise UnsupportedPatternError(f"matcher object must have exactly one key: {matcher!r}")
    ((name, argument),) = matcher.items()
    if name not in _SUPPORTED_MATCHERS:
        raise UnsupportedPatternError(f"matcher {name!r} is not implemented")

    if name == "exists":
        if not isinstance(argument, bool):
            raise UnsupportedPatternError("exists takes a boolean")
        return (actual is not _MISSING) is argument

    if actual is _MISSING:
        return False

    if name == "anything-but":
        return not _anything_but(argument, actual)

    if isinstance(actual, list):
        return any(_match_scalar(name, argument, item) for item in actual)
    return _match_scalar(name, argument, actual)


def _anything_but(argument: Any, actual: Any) -> bool:
    """True when ``actual`` matches the excluded set."""
    if isinstance(argument, Mapping):
        return _match_matcher_object(argument, actual)
    if isinstance(argument, list):
        return any(item == actual for item in argument)
    return bool(argument == actual)


def _match_scalar(name: str, argument: Any, actual: Any) -> bool:
    if name == "prefix":
        return isinstance(actual, str) and actual.startswith(str(argument))
    if name == "suffix":
        return isinstance(actual, str) and actual.endswith(str(argument))
    if name == "equals-ignore-case":
        return isinstance(actual, str) and actual.lower() == str(argument).lower()
    if name == "wildcard":
        return isinstance(actual, str) and fnmatch.fnmatchcase(actual, str(argument))
    if name == "numeric":
        return _numeric(argument, actual)
    raise UnsupportedPatternError(f"matcher {name!r} is not implemented")


def _numeric(argument: Any, actual: Any) -> bool:
    if not isinstance(argument, list) or len(argument) % 2 != 0:
        raise UnsupportedPatternError("numeric takes [op, value] pairs")
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return False

    for index in range(0, len(argument), 2):
        operator = str(argument[index])
        threshold = float(argument[index + 1])
        number = float(actual)
        if operator == "=" and number != threshold:
            return False
        if operator == "<" and not number < threshold:
            return False
        if operator == "<=" and not number <= threshold:
            return False
        if operator == ">" and not number > threshold:
            return False
        if operator == ">=" and not number >= threshold:
            return False
        if operator not in {"=", "<", "<=", ">", ">="}:
            raise UnsupportedPatternError(f"numeric operator {operator!r} is not implemented")
    return True
