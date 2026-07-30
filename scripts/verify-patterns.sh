#!/usr/bin/env bash
# B2 gate: ask EventBridge itself whether each pattern matches each fixture.
#
# ADR-010 reimplements the EventBridge pattern language so the unit tests can
# run with no AWS account. That is a convenience, not an authority: the only
# evaluator that decides whether a detection fires in production is the service.
# This script closes that gap by replaying every committed fixture through
# `aws events test-event-pattern`.
#
# It needs credentials and nothing else. No Lambda, no EventBridge rule and no
# deployed stack has to exist, which is why this runs before the apply is
# finished rather than after.
#
# Expectation comes from the filename: `benign-*` must NOT match, everything
# else must. A pattern that matches its benign fixture is worse than a broken
# one, because it looks like coverage while remediating normal traffic.
#
#   ./scripts/verify-patterns.sh          # calls AWS
#   ./scripts/verify-patterns.sh --list   # resolve fixtures only, no AWS call
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

LIST_ONLY=0
[ "${1:-}" = "--list" ] && LIST_ONLY=1

command -v jq >/dev/null || { echo "jq is not installed" >&2; exit 1; }
if [ "${LIST_ONLY}" -eq 0 ]; then
  command -v aws >/dev/null || { echo "aws is not installed" >&2; exit 1; }
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

checked=0
failures=0

for pattern in detections/*/pattern.json; do
  detection="$(basename "$(dirname "${pattern}")")"

  # Fixtures live under the bus that carries the event, not under the detection.
  fixture_dir=""
  for candidate in tests/fixtures/*/"${detection}"; do
    [ -d "${candidate}" ] && fixture_dir="${candidate}"
  done
  if [ -z "${fixture_dir}" ]; then
    printf '  NO FIXTURES  %s\n' "${detection}" >&2
    failures=$((failures + 1))
    continue
  fi

  for fixture in "${fixture_dir}"/*.json; do
    name="$(basename "${fixture}" .json)"
    case "${name}" in
      benign-*) expected="false" ;;
      *) expected="true" ;;
    esac

    if [ "${LIST_ONLY}" -eq 1 ]; then
      printf '  %-14s %-46s expect %s\n' "${detection}" "${name}" "${expected}"
      checked=$((checked + 1))
      continue
    fi

    # `_pac_fixture` is this repo's provenance marker, not part of the event.
    # It is stripped so the service sees exactly what CloudTrail would deliver.
    jq -c 'del(._pac_fixture)' "${fixture}" >"${work}/event.json"

    actual="$(aws events test-event-pattern \
      --event-pattern "file://${root}/${pattern}" \
      --event "file://${work}/event.json" \
      --query Result --output text)"
    actual="$(printf '%s' "${actual}" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"

    checked=$((checked + 1))
    if [ "${actual}" = "${expected}" ]; then
      printf '  ok    %-14s %-46s %s\n' "${detection}" "${name}" "${actual}"
    else
      printf '  FAIL  %-14s %-46s expected %s, service said %s\n' \
        "${detection}" "${name}" "${expected}" "${actual}"
      failures=$((failures + 1))
    fi
  done
done

if [ "${LIST_ONLY}" -eq 1 ]; then
  printf '\n%d fixtures resolved, %d without a pattern. No AWS call was made.\n' \
    "${checked}" "${failures}"
  [ "${failures}" -eq 0 ] || exit 1
  exit 0
fi

printf '\n%d fixtures, %d disagreements with the service\n' "${checked}" "${failures}"
if [ "${failures}" -ne 0 ]; then
  echo "A disagreement here means the detection is dead in production regardless of the unit tests." >&2
  exit 1
fi
