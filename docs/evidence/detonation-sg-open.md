# Detonation — `sg-open`

`aws.exfiltration.ec2-security-group-open-port-22-ingress`, Stratus Red Team
v2.34.1, isolated lab account, **2026-07-30**. This is the run that found two
defects no unit test could have found.

## The pattern matched the wrong event

First detonation, `dry_run = true`. The rule fired once and the audit record
said:

```text
status  SKIPPED
reason  triggered by this system's own remediation role
```

Two things were wrong in that one record.

### 1. The loop guard was an attacker-controlled bypass

`Principal.is_pac_automation()` tested `"pac-" in self.arn`. An assumed-role ARN
is `arn:aws:sts::<account>:assumed-role/<role>/<session>`, and the session name
is chosen freely by the caller on every `AssumeRole`. Stratus happened to run
under a session called `pac-terraform`, so the detection classified the attack
as its own automation and skipped it.

Any attacker passing `--role-session-name pac-anything` was invisible. A
detection bypass the attacker selects is worse than having no loop guard at
all, because the audit trail records a confident `SKIPPED`.

The comparison is now against the role name only, which is fixed when the role
is created rather than chosen at assume time.

### 2. The rule matched the warm-up, not the attack

With the guard fixed, the technique was detonated again — and nothing
happened. `MatchedEvents` on the rule showed exactly one match, at the time of
the *first* detonation, and CloudTrail explained why:

```json
// Terraform warm-up, port 443 — matched
{"ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
  "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}

// Stratus, port 22 — did not match
{"ipPermissions": {}, "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
 "cidrIp": "0.0.0.0/0"}
```

`AuthorizeSecurityGroupIngress` has two CloudTrail encodings for the same call.
The AWS CLI sends `IpPermissions` and CloudTrail records the nested form. A
caller using the legacy top-level parameters produces an empty `ipPermissions`
with `ipProtocol`, `fromPort`, `toPort` and `cidrIp` directly on
`requestParameters`.

Every fixture in this repository had been produced by the CLI, so the pattern
had only ever seen one of the two. The unit tests were green throughout, the
pattern gate agreed with EventBridge throughout, and the detection was blind to
an attacker using the older parameter form.

The pattern now carries both encodings, for IPv4 and IPv6. The handler needed
no change: it reads the security group back rather than trusting the event,
which is the design decision that limited this to a missed detection instead of
a wrong remediation.

## After the fixes

| Run | `dry_run` | Result |
|---|---|---|
| 3rd detonation | `true` | `DRY_RUN`, full snapshot, port 22 **still open** afterwards |
| 4th detonation | `false` | `APPLIED` in **5.97 s**, port 22 revoked, port 443 untouched |

Numbers and the circuit-breaker run are in
[time-to-remediate.md](time-to-remediate.md).

## Cleanup

`stratus revert` failed on the live run because the remediation had already
revoked the rule — the intended outcome, recorded here so the warning in the
log is not mistaken for a fault. `stratus cleanup --force` then destroyed the
prerequisites.

```text
stratus status        no technique WARM or DETONATED
EC2 instances         0
S3 buckets            0
dead-letter queues    0 messages in all three
security group        deleted with the technique's Terraform
```

## Why this is the evidence that matters

The repository's claim is that a detection is only real once it has been proven
by attacking the account. Every gate was green throughout: 174 unit tests at the
first detonation and 176 at the second, a pattern gate agreeing with EventBridge
on every fixture, and fourteen of fifteen fixtures captured from real CloudTrail
events.

All of it was consistent with a detection that does not fire on the attack it
was written for.
