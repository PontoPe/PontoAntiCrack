# Attack simulation

> **Nothing in here has been executed.** The scenarios and assertions are
> written and ready. Running them detonates real attack techniques against a
> real AWS account, and that is a decision made in front of the keyboard with
> the account ID on screen — not something a session of automated work gets to
> do on your behalf.

## Why this exists

A detection that has never seen the technique it claims to detect is a
hypothesis. The unit tests in `tests/` prove the pattern matches the event we
*think* AWS produces; only detonation proves AWS produces that event.

This is also the part that produces the number worth putting in a README:
time-to-remediate, measured, in a named account, on a date.

## Guards

Three, in order:

1. `make attack` prints the resolved account ID and requires you to type `y`.
2. `assert.sh` and `measure.sh` refuse to run unless `STRATUS_LAB_ACCOUNT_ID`
   is exported **and** equals the account the current credentials resolve to.
   The realistic failure is a stale SSO session pointed somewhere else; this
   catches it.
3. The live CI job is gated behind a manual-approval environment and never runs
   on a pull request from a fork.

## Running it

```bash
export AWS_PROFILE=lab
export STRATUS_LAB_ACCOUNT_ID=<the lab account id>

stratus list
make attack TTP=aws.exfiltration.ec2-security-group-open-port-22-ingress
```

`make attack` detonates, asserts, and cleans up. `stratus cleanup` is not
optional — Stratus leaves instances and buckets behind, and a lab account with
a forgotten `t3.micro` in it eats a month of the budget.

For the full measurement pass:

```bash
./attack-sim/measure.sh > docs/evidence/time-to-remediate.md
```

## Scenarios

See [`scenarios.yaml`](scenarios.yaml) for the assertions. Two caveats that
matter before the first run:

**`s3-public`** — the stock `aws.exfiltration.s3-backdoor-bucket-policy` scenario grants
access to a *specific external account*, not to `AllUsers`. The handler treats a
named external principal as not-public, on purpose. So this scenario may
correctly produce no remediation, and that would be the detection working, not
failing. Proving the public path probably needs a custom scenario that grants to
`AllUsers`.

**`iam-key-leak`** — `ec2-steal-instance-credentials` produces a GuardDuty
finding about an *assumed-role session*. Temporary credentials cannot be
deactivated with `UpdateAccessKey`, so the expected outcome is `ESCALATED`, not
`APPLIED`. Exercising the `APPLIED` path needs a long-lived IAM user key used
from a flagged IP, which Stratus does not ship.

**`sg-open`** is the clean one: CloudTrail is immediate, the pattern is exact,
the remediation is one API call. Start here.

## Order of first run

1. `sg-open` with `dry_run = true`. Confirm the event arrives and the plan is
   right, having changed nothing.
2. Capture the delivered event from the function's log group and replace the
   documentation-derived fixture with it.
3. Re-run the unit tests against the real event.
4. Only then `dry_run = false`, and re-detonate.

Step 2 is the one that turns this repository's central claim from a plan into a
fact.
