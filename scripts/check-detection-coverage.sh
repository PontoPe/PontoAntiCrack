#!/usr/bin/env bash
# CI gate: no detection ships without the whole unit.
#
# A detection is a pattern, a handler, a scoped IAM policy, a README, a set of
# fixtures, and tests that assert both that the pattern matches and that it does
# NOT match the plausible-but-benign case. A partial one is worse than none: it
# looks like coverage on the README table while matching nothing, or matching
# everything.
#
# This also enforces the negative test. A detection with only positive tests
# passes CI forever while quietly matching every event in the account, and the
# first person to find out is whoever is paged by the remediation storm.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

failures=0

fail() {
  printf '  MISSING  %s\n' "$1"
  failures=$((failures + 1))
}

if [ ! -d detections ] || [ -z "$(find detections -mindepth 1 -maxdepth 1 -type d)" ]; then
  echo "no detections found under detections/ — nothing to check" >&2
  exit 1
fi

for dir in detections/*/; do
  id="$(basename "${dir}")"
  package="${id//-/_}"
  printf 'detection %s\n' "${id}"

  [ -f "${dir}pattern.json" ] || fail "${dir}pattern.json"
  [ -f "${dir}metadata.yaml" ] || fail "${dir}metadata.yaml"

  [ -f "remediations/${package}/handler.py" ] || fail "remediations/${package}/handler.py"
  [ -f "remediations/${package}/policy.json" ] || fail "remediations/${package}/policy.json"
  [ -f "remediations/${package}/README.md" ] || fail "remediations/${package}/README.md"

  pattern_test="tests/detections/test_${package}_pattern.py"
  handler_test="tests/remediations/test_${package}_handler.py"
  [ -f "${pattern_test}" ] || fail "${pattern_test}"
  [ -f "${handler_test}" ] || fail "${handler_test}"

  # Fixtures live under whichever source this detection consumes.
  fixture_dir=""
  for category in cloudtrail guardduty; do
    if [ -d "tests/fixtures/${category}/${id}" ]; then
      fixture_dir="tests/fixtures/${category}/${id}"
      break
    fi
  done
  if [ -z "${fixture_dir}" ]; then
    fail "tests/fixtures/{cloudtrail,guardduty}/${id}/"
  else
    count="$(find "${fixture_dir}" -name '*.json' | wc -l | tr -d ' ')"
    [ "${count}" -ge 2 ] || fail "${fixture_dir} has ${count} fixture(s); need at least a matching one and a benign one"
    benign="$(find "${fixture_dir}" -name 'benign-*.json' | wc -l | tr -d ' ')"
    [ "${benign}" -ge 1 ] || fail "${fixture_dir}/benign-*.json — a detection with no false-positive fixture is untested where it matters"
  fi

  # The negative assertion has to exist in the test file, not just the fixture.
  if [ -f "${pattern_test}" ] && ! grep -q 'assert not matches' "${pattern_test}"; then
    fail "${pattern_test} has no 'assert not matches' — the pattern is only tested for what it catches"
  fi

  # ATT&CK mapping, so the README table and docs/mitre-attack.md cannot drift
  # away from what is deployed.
  grep -q "\`${id}\`" docs/mitre-attack.md 2>/dev/null || fail "docs/mitre-attack.md entry for ${id}"
done

if [ "${failures}" -gt 0 ]; then
  printf '\n%d missing artefact(s). A detection is a unit: pattern, handler, policy, README, fixtures, and tests for both the match and the near-miss.\n' "${failures}" >&2
  exit 1
fi

printf '\nall detections complete\n'
