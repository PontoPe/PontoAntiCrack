# Evidence

Generated artifacts that back the claims in the README: time-to-remediate
measurements, before/after resource state, exported GuardDuty findings.
Committed on purpose — the proof is the deliverable.

**Four artifacts, and the claim on the README is now true.**

`pattern-gate.md` records EventBridge agreeing with all fifteen fixtures, which
closes the limitation ADR-010 documents. `fixture-capture.md` records the
fixtures becoming real events rather than documentation, and the five places
where real events disagreed with the hand-written ones.
`detonation-sg-open.md` and `time-to-remediate.md` record the technique being
detonated for real, the two defects that only a detonation could find, and the
measured window between the attacker's API call and the rule being revoked.

One technique has been detonated and one remediation has run against a real
resource. `s3-public` and `iam-key-leak` have not been detonated, so their
latency is unmeasured and no number for them appears here.

What will land here, and what produces it:

| File | Produced by | Claim it backs |
|---|---|---|
| `pattern-gate.md` ✅ | `make patterns` | That the service, not a local reimplementation, agrees with every pattern on every fixture |
| `fixture-capture.md` ✅ | Real API calls in the lab, then `lookup-events` | That fifteen of seventeen fixtures are recorded events, and what changed when they stopped being guesses |
| `time-to-remediate.md` ✅ | the live `sg-open` detonation | The window between the attacker's API call and the rule being revoked: 5.97 s, once, in the lab |
| `detonation-sg-open.md` ✅ | Stratus Red Team v2.34.1 | That the technique was executed, and the two defects it exposed that every green gate had missed |
| `false-positive-review.md` | Reviewing `SKIPPED`/`DRY_RUN` audit records after a week of real traffic | That this is safe to let act |

The order matters: the last one is the one that justifies `dry_run = false`
outside the lab.
