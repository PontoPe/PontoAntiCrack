#!/usr/bin/env bash
#
# Deterministic replay of the recorded lab detonation.
#
# It makes no AWS call, takes no argument and reads one committed file. The
# numbers on screen are the ones in docs/evidence/time-to-remediate.md, and the
# file is validated against an exact expected shape first — a demo that renders
# whatever it is handed is a screenshot, not evidence.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
EVIDENCE="$REPO/docs/evidence/detonation-replay.json"

if [ ! -f "$EVIDENCE" ]; then
  printf 'demo evidence is not available\n' >&2
  exit 1
fi

if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; Z=$'\033[0m'
else
  B=""; G=""; R=""; Y=""; D=""; Z=""
fi

printf '%sPontoAntiCrack — detection and remediation, replayed%s\n\n' "$B" "$Z"
printf '%s# Recorded in an isolated lab account. No AWS call is made by this demo.%s\n' "$D" "$Z"
printf '%s# Account IDs, ARNs and resource IDs are redacted.%s\n\n' "$D" "$Z"

python3 - "$EVIDENCE" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, UnicodeError, json.JSONDecodeError):
    print("evidence validation failed", file=sys.stderr)
    raise SystemExit(1)

expected = {
    "schema": "pac-detonation-replay/v1",
    "technique": "aws.exfiltration.ec2-security-group-open-port-22-ingress",
    "tool": "Stratus Red Team v2.34.1",
    "environment": "lab",
    "dry_run_first": {
        "status": "DRY_RUN",
        "intended_action": "revoke ingress tcp/22-22 from 0.0.0.0/0 from sg-0123456789abcdef0",
        "resource_changed": False,
    },
    "live": {
        "status": "APPLIED",
        "event_time": "2026-07-31T00:07:52Z",
        "completed_at": "2026-07-31T00:07:57.971016Z",
        "seconds_to_remediate": 5.97,
        "action": "revoked ingress tcp/22-22 from 0.0.0.0/0 from sg-0123456789abcdef0",
    },
    "scoping": {
        "rules_before": 2,
        "rules_revoked": 1,
        "preserved": "tcp/443 from 0.0.0.0/0",
    },
    "circuit_breaker": {"blocked_records": 4, "max_actions_per_window": 5},
}

if data != expected:
    print("evidence validation failed", file=sys.stderr)
    raise SystemExit(1)
PY

printf '%sPontoAntiCrack — detection and remediation, replayed%s\n\n' "$B" "$Z"
printf '%s# Recorded in an isolated lab account. No AWS call is made by this demo.%s\n' "$D" "$Z"
printf '%s# Account IDs, ARNs and resource IDs are redacted.%s\n\n' "$D" "$Z"

printf '%s$ stratus detonate aws.exfiltration.ec2-security-group-open-port-22-ingress%s\n' "$B" "$Z"
printf '  opened tcp/22 to 0.0.0.0/0 on sg-0123456789abcdef0\n\n'

printf '%s$ dry run first%s\n' "$B" "$Z"
printf '%sDRY_RUN%s  would revoke tcp/22 from 0.0.0.0/0 — resource left unchanged\n\n' "$Y" "$Z"

printf '%s$ live remediation%s\n' "$B" "$Z"
printf '%sAPPLIED%s  revoked tcp/22 from 0.0.0.0/0\n' "$G" "$Z"
printf '         %s5.97 s%s from the attacker API call to the rule being gone\n' "$B" "$Z"
printf '         2 rules before, 1 revoked — tcp/443 left alone\n\n'

printf '%s$ seven world-open ports in eighty seconds%s\n' "$B" "$Z"
printf '%sBLOCKED%s  circuit breaker held after 5 actions; 4 refusals recorded\n\n' "$R" "$Z"

printf '%sA remediation that cannot stop is a weapon pointed at its own account.%s\n' "$B" "$Z"
