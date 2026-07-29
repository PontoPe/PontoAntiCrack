#!/usr/bin/env bash
# Time-to-remediate, measured rather than asserted.
#
#   ./attack-sim/measure.sh > docs/evidence/time-to-remediate.md
#
# NEVER RUN THIS OUTSIDE THE ISOLATED LAB ACCOUNT. It detonates real techniques.
#
# The number this produces is the point of the whole repository: not "there is a
# detection" but "the window between the attacker's API call and the resource
# being closed was N seconds, measured, on this date, in this account".
#
# Three timestamps per run:
#   t_attack     when the technique executed (local clock)
#   t_event      CloudTrail eventTime from the audit record (AWS clock)
#   t_remediated completed_at from the audit record
#
# t_event - t_attack is delivery latency, which is AWS's and is mostly out of
# our hands. t_remediated - t_event is ours, and is the number worth reporting.

set -euo pipefail

table="${PAC_TABLE_NAME:-pac-audit}"
timeout="${PAC_ASSERT_TIMEOUT:-600}"

if [ -z "${STRATUS_LAB_ACCOUNT_ID:-}" ]; then
  echo "refusing to run: STRATUS_LAB_ACCOUNT_ID is not set" >&2
  exit 78
fi

current_account="$(aws sts get-caller-identity --query Account --output text)"
if [ "${current_account}" != "${STRATUS_LAB_ACCOUNT_ID}" ]; then
  echo "refusing to run: credentials resolve to ${current_account}, not ${STRATUS_LAB_ACCOUNT_ID}" >&2
  exit 77
fi

scenarios=(
  "sg-open:aws.defense-evasion.security-group-open-port-22-ingress"
  "s3-public:aws.exfiltration.s3-backdoor"
  "iam-key-leak:aws.credential-access.ec2-steal-instance-credentials"
)

cat <<EOF
# Time to remediate

Measured in account \`${current_account}\` on $(date -u +%Y-%m-%dT%H:%M:%SZ).

\`t_event\` is the CloudTrail \`eventTime\`; \`t_remediated\` is \`completed_at\`
from the audit record. The delta between them is this system's latency. The
delta between detonation and \`t_event\` is event delivery, which belongs to AWS.

| Detection | Technique | Delivery (s) | Remediation (s) | Total (s) | Status |
|---|---|---|---|---|---|
EOF

for entry in "${scenarios[@]}"; do
  detection="${entry%%:*}"
  ttp="${entry#*:}"

  t_attack="$(date -u +%s)"
  stratus detonate "${ttp}" > /dev/null 2>&1 || {
    printf '| `%s` | `%s` | — | — | — | detonation failed |\n' "${detection}" "${ttp}"
    continue
  }

  deadline=$(( $(date +%s) + timeout ))
  record=""
  while [ "$(date +%s)" -lt "${deadline}" ]; do
    record="$(aws dynamodb scan \
      --table-name "${table}" \
      --filter-expression 'begins_with(pk, :p) AND attribute_exists(completed_at)' \
      --expression-attribute-values "{\":p\":{\"S\":\"AUDIT#${detection}#\"}}" \
      --output json \
      | jq -r '[.Items[]?] | sort_by(.recorded_at.S) | last // empty')"
    [ -n "${record}" ] && break
    sleep 5
  done

  if [ -z "${record}" ]; then
    printf '| `%s` | `%s` | — | — | — | no audit record within %ss |\n' \
      "${detection}" "${ttp}" "${timeout}"
    stratus cleanup "${ttp}" > /dev/null 2>&1 || true
    continue
  fi

  event_time="$(printf '%s' "${record}" | jq -r '.event_time.S')"
  completed="$(printf '%s' "${record}" | jq -r '.completed_at.S')"
  status="$(printf '%s' "${record}" | jq -r '.status.S')"

  t_event="$(date -u -d "${event_time}" +%s)"
  t_done="$(date -u -d "${completed}" +%s)"

  printf '| `%s` | `%s` | %s | %s | %s | %s |\n' \
    "${detection}" "${ttp}" \
    "$(( t_event - t_attack ))" \
    "$(( t_done - t_event ))" \
    "$(( t_done - t_attack ))" \
    "${status}"

  stratus cleanup "${ttp}" > /dev/null 2>&1 || true
done

cat <<'EOF'

## Reading this

A `no audit record` row is not a slow detection, it is a broken one. Work
through the checklist in `attack-sim/assert.sh` before re-running.

`iam-key-leak` is expected to report `ESCALATED`, not `APPLIED`: the Stratus
scenario produces a finding about a temporary session credential, which cannot
be deactivated. Its "remediation" time is the time to alert a human.

GuardDuty findings are not real-time. Expect delivery in the tens of minutes for
`iam-key-leak`, against seconds for the two CloudTrail-driven detections. That
difference is a property of the signal, not of this code, and reporting them in
the same column without saying so would be misleading.
EOF
