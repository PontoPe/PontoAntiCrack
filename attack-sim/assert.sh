#!/usr/bin/env bash
# Assert that a detonated technique was actually detected and remediated.
#
#   ./attack-sim/assert.sh <ttp> [resource-id]
#
# NEVER RUN THIS OUTSIDE THE ISOLATED LAB ACCOUNT. It reads the live audit table
# and the live resource. It changes nothing itself, but it is only meaningful
# immediately after `stratus detonate`, which very much does.
#
# The guard below is not a formality: STRATUS_LAB_ACCOUNT_ID must be exported
# AND must equal the account the current credentials resolve to. A stale SSO
# session pointed at the wrong account is the realistic failure mode, and it is
# the one this catches.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: assert.sh <ttp> [resource-id]

  ttp          Stratus Red Team technique ID, e.g. aws.defense-evasion.security-group-open-port-22-ingress
  resource-id  Resource to assert on. Discovered from the audit table if omitted.

required environment:
  STRATUS_LAB_ACCOUNT_ID  the isolated lab account. Must match the caller identity.
  PAC_TABLE_NAME          audit table name (default: pac-audit)
EOF
  exit 64
}

[ $# -ge 1 ] || usage

ttp="$1"
resource="${2:-}"
table="${PAC_TABLE_NAME:-pac-audit}"
timeout="${PAC_ASSERT_TIMEOUT:-300}"
interval="${PAC_ASSERT_INTERVAL:-5}"

# --- guard ------------------------------------------------------------------

if [ -z "${STRATUS_LAB_ACCOUNT_ID:-}" ]; then
  echo "refusing to run: STRATUS_LAB_ACCOUNT_ID is not set" >&2
  exit 78
fi

current_account="$(aws sts get-caller-identity --query Account --output text)"
if [ "${current_account}" != "${STRATUS_LAB_ACCOUNT_ID}" ]; then
  cat >&2 <<EOF
refusing to run.

  credentials resolve to : ${current_account}
  declared lab account   : ${STRATUS_LAB_ACCOUNT_ID}

These must match. If ${current_account} is a real account, stop and re-authenticate.
EOF
  exit 77
fi

# --- what are we asserting --------------------------------------------------

case "${ttp}" in
  aws.exfiltration.s3-backdoor)
    detection="s3-public"
    expected_status="APPLIED"
    ;;
  aws.credential-access.ec2-steal-instance-credentials)
    detection="iam-key-leak"
    # Temporary credentials cannot be deactivated; the handler escalates.
    expected_status="ESCALATED"
    ;;
  aws.defense-evasion.security-group-open-port-22-ingress)
    detection="sg-open"
    expected_status="APPLIED"
    ;;
  *)
    echo "no assertion defined for ${ttp}. See attack-sim/scenarios.yaml." >&2
    exit 64
    ;;
esac

printf 'detection      : %s\n' "${detection}"
printf 'expected status: %s\n' "${expected_status}"
printf 'audit table    : %s\n' "${table}"
printf 'waiting up to  : %ss\n\n' "${timeout}"

# --- poll the audit table ---------------------------------------------------

query_audit() {
  local key_prefix="AUDIT#${detection}"
  if [ -n "${resource}" ]; then
    key_prefix="${key_prefix}#${resource}"
    aws dynamodb query \
      --table-name "${table}" \
      --key-condition-expression 'pk = :pk' \
      --expression-attribute-values "{\":pk\":{\"S\":\"${key_prefix}\"}}" \
      --output json
  else
    # No resource known yet: Stratus names it at detonation time. Scan is
    # acceptable here — this table is small and this is not a hot path.
    aws dynamodb scan \
      --table-name "${table}" \
      --filter-expression 'begins_with(pk, :prefix)' \
      --expression-attribute-values "{\":prefix\":{\"S\":\"${key_prefix}#\"}}" \
      --output json
  fi
}

deadline=$(( $(date +%s) + timeout ))
found=""

while [ "$(date +%s)" -lt "${deadline}" ]; do
  items="$(query_audit)"
  found="$(printf '%s' "${items}" \
    | jq -r --arg want "${expected_status}" \
      '[.Items[]? | select(.status.S == $want)] | sort_by(.recorded_at.S) | last // empty')"
  if [ -n "${found}" ]; then
    break
  fi
  printf '.'
  sleep "${interval}"
done
printf '\n'

if [ -z "${found}" ]; then
  cat >&2 <<EOF
FAIL: no ${expected_status} audit record for ${detection} within ${timeout}s.

Check, in this order:
  1. Did the technique actually run?           stratus status
  2. Did the rule match?                       aws logs tail /aws/lambda/pac-${detection} --since 10m
  3. Was the event delivered at all?           TriggeredRules metric on the rule
  4. Is the pattern wrong?                     aws events test-event-pattern --event-pattern file://detections/${detection}/pattern.json --event <the real event>

(4) is the likely one until the fixtures have been confirmed against real
events. See docs/session-report.md.
EOF
  exit 1
fi

resource="$(printf '%s' "${found}" | jq -r '.resource_id.S')"
recorded="$(printf '%s' "${found}" | jq -r '.recorded_at.S')"
completed="$(printf '%s' "${found}" | jq -r '.completed_at.S // "n/a"')"

printf 'PASS: %s recorded %s for %s\n' "${detection}" "${expected_status}" "${resource}"
printf '  detected   : %s\n' "${recorded}"
printf '  completed  : %s\n' "${completed}"
printf '  actions    : %s\n' "$(printf '%s' "${found}" | jq -r '[.actions.L[]?.S] | join("; ")')"

# --- assert the resource actually changed -----------------------------------
#
# The audit record says what we believe we did. This says what is true.

case "${detection}" in
  s3-public)
    echo
    echo "resource state:"
    aws s3api get-public-access-block --bucket "${resource}" --output json \
      | jq -e '.PublicAccessBlockConfiguration
               | .BlockPublicAcls and .IgnorePublicAcls
                 and .BlockPublicPolicy and .RestrictPublicBuckets' > /dev/null \
      || { echo "FAIL: Block Public Access is not fully enabled on ${resource}" >&2; exit 1; }
    echo "  block public access: all four enabled"

    # The policy must still exist. Deleting it would have destroyed evidence.
    if aws s3api get-bucket-policy --bucket "${resource}" > /dev/null 2>&1; then
      echo "  bucket policy      : retained (correct — BPA neutralises it, deletion would destroy evidence)"
    else
      echo "FAIL: the bucket policy is gone. The remediation destroyed IR evidence." >&2
      exit 1
    fi
    ;;

  sg-open)
    echo
    echo "resource state:"
    open_ssh="$(aws ec2 describe-security-groups --group-ids "${resource}" --output json \
      | jq '[.SecurityGroups[0].IpPermissions[]
             | select((.FromPort // 0) <= 22 and (.ToPort // 65535) >= 22)
             | .IpRanges[].CidrIp] | index("0.0.0.0/0")')"
    [ "${open_ssh}" = "null" ] \
      || { echo "FAIL: ${resource} still allows 0.0.0.0/0 on port 22" >&2; exit 1; }
    echo "  world-open ssh     : revoked"
    echo
    echo "Check by hand that nothing else was revoked:"
    echo "  diff <(jq -r '.snapshot.S' <<< '${found}' | jq .ip_permissions_before) \\"
    echo "       <(aws ec2 describe-security-groups --group-ids ${resource} | jq '.SecurityGroups[0].IpPermissions')"
    ;;

  iam-key-leak)
    echo
    echo "resource state:"
    echo "  ${expected_status} means no state change was expected. Confirm none happened:"
    echo "    aws iam list-access-keys --user-name <user>"
    ;;
esac

echo
echo "OK"
