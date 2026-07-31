# Time to remediate — measured

`sg-open`, in the isolated lab account, on **2026-07-30**. The attack was
executed by Stratus Red Team v2.34.1 detonating
`aws.exfiltration.ec2-security-group-open-port-22-ingress`; the binary was
verified against the published SHA-256 in the release's `checksums.txt` before
it was run.

## The number

```text
attacker's API call (CloudTrail eventTime)   2026-07-31T00:07:52Z
rule revoked        (audit completed_at)     2026-07-31T00:07:57.971016Z
                                             -----------------------
time to remediate                                    5.97 seconds
```

One detection, one measurement, one account. It is not a distribution and is
not claimed as one.

The window covers CloudTrail delivery to EventBridge, the rule match, a cold
Lambda invocation, reading the security group back, writing the prior-state
snapshot, and the `RevokeSecurityGroupIngress` call. AWS's delivery latency is
inside that number and is the part nobody here controls.

## What was revoked, and what was not

The group carried two world-open rules: port 22 from the detonation and port
443 from the technique's own Terraform warm-up.

```json
"ip_permissions_revoked": [
  {"FromPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 22}
]
```

Port 443 survived. `COMMONLY_PUBLIC_PORTS` exists so that a remediation aimed
at SSH does not take a web listener down with it — threat R2, over-broad
remediation, is the failure mode that turns a security control into an outage.
The audit item holds `ip_permissions_before` with both rules, so the decision
is reconstructible after the fact.

## Dry run first, and it meant it

The same technique was detonated with `dry_run = true` before the live run.

```text
status   DRY_RUN
reason   security group ... allows ingress from the internet on 22
actions  revoke ingress tcp/22-22 from 0.0.0.0/0 from sg-...
```

The security group was checked immediately afterwards and port 22 was still
open to `0.0.0.0/0`. A dry run that changes anything is not a dry run, and the
snapshot was written in that mode too — so the record is complete whether or
not the action runs.

## The circuit breaker, tripped on purpose

Seven world-open ports were opened in eighty seconds: 23, 25, 1521, 3306, 8080,
9200, 11211. The breaker allows five actions per five-minute window and counts
dry runs.

```text
00:06:00  DRY_RUN   port 22     (action 1)
00:07:52  APPLIED   port 22     (action 2)
00:08:31  APPLIED   port 23     (action 3)
00:08:35  APPLIED   port 25     (action 4)
00:08:39  APPLIED   port 1521   (action 5)
00:08:43  BLOCKED   port 3306
00:08:48  BLOCKED   port 3306, 8080
00:08:52  BLOCKED   port 3306, 8080, 9200
00:08:56  BLOCKED   port 3306, 8080, 9200, 11211
```

Four `BLOCKED` records, and the four ports stayed open. That is the correct
outcome and the uncomfortable one: a system that keeps acting through an
anomaly is indistinguishable from a system being used as a weapon against its
own account. The breaker chooses "stop and tell someone" over "keep going", and
the audit trail names every resource it declined to touch.

The four ports were revoked by hand afterwards, and the Stratus infrastructure
was destroyed. `stratus status` reports no technique in `WARM` or `DETONATED`,
no instances and no buckets remain, and all three dead-letter queues are empty.

## What this does not measure

- **One detection, once.** `s3-public` and `iam-key-leak` were not detonated;
  their remediation latency is unmeasured.
- **A cold start is in the number.** A warm function would be faster, and a
  first invocation after a deploy would be slower.
- **No false-positive rate.** Measuring that needs `dry_run = true` against a
  week of real traffic, which the lab does not have.
- **The Slack path is unproven.** No webhook exists, so alert delivery is not
  part of this measurement. The audit record, not the chat message, is the
  system of record.
