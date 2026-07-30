# Evidence

Generated artifacts that back the claims in the README: time-to-remediate
measurements, before/after resource state, exported GuardDuty findings.
Committed on purpose — the proof is the deliverable.

**One artifact so far, and that is the accurate state.**

`pattern-gate.md` records EventBridge agreeing with all fifteen fixtures, which
closes the limitation ADR-010 documents. Nothing has been detonated yet, no
remediation has run against a real resource, and no latency has been measured.
Until `attack-sim/measure.sh` has been run in the lab account, there is nothing
honest to put here about remediation, and a plausible-looking table of numbers
would be worse than an absent one.

What will land here, and what produces it:

| File | Produced by | Claim it backs |
|---|---|---|
| `pattern-gate.md` ✅ | `make patterns` | That the service, not a local reimplementation, agrees with every pattern on every fixture |
| `time-to-remediate.md` | `make timing` | The window between the attacker's API call and the resource being closed, per detection, measured |
| `detonation-<ttp>.md` | `make attack TTP=…` output, saved by hand | That the technique was executed and the assertion passed |
| `false-positive-review.md` | Reviewing `SKIPPED`/`DRY_RUN` audit records after a week of real traffic | That this is safe to let act |

The order matters: the last one is the one that justifies `dry_run = false`
outside the lab.
