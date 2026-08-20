# PontoAntiCrack (PAC) — context for coding agents

Read this before touching anything. It is the handoff between sessions.

Full project handoff — current state, what is proven vs. claimed, the exact next
actions, and every known gap: **`docs/PAChandoff.md`**.

How things get built here — build order, the ten-gate validation loop, the
defects it caught, and the checklist for adding a detection:
**`docs/PAChandbook.md`**.

## What this is

Detection-as-code and automated remediation for AWS: CloudTrail → EventBridge → Lambda, with every detection written as tested code and validated by detonating the real attack technique against an isolated lab account.

Named after VAC — anti-cheat for cloud accounts. The game keeps running; the cheater gets caught and kicked automatically.

This is the repo that moves the owner from "sysadmin who knows security" to "security engineer". The differentiator is not that detections exist — it is that they have **unit tests on recorded CloudTrail events** and were **proven by attacking the account**, with time-to-remediate measured.

Owner: Pedro (GitHub `PontoPe`). Repo: `github.com/PontoPe/PontoAntiCrack`, **public** since 2026-08 — the history was scrubbed of the lab account ID before it was published, so keep account IDs out of anything committed here.

## Where things stand (2026-08-15)

**Deployed to `awlz-lab`, wired to EventBridge, detonated, measured, public.**
`sg-open` revoked a world-open SSH rule **5.97 s** after the attacker's API
call. The lab has run with `dry_run = false` since 2026-07-31. Blow-by-blow in
`docs/PROGRESS.md`; the cold-start orientation is `docs/PAChandoff.md`.

Done:

- `infra/` — Terraform for all three detections: EventBridge rule, Lambda, one execution role each, DynamoDB audit table, one KMS CMK, Secrets Manager secret, per-detection SQS DLQ, nine alarms. `validate`/`tflint`/`trivy`/`checkov` all clean.
- `detections/` — three EventBridge patterns + ATT&CK and provenance metadata.
- `remediations/` — three handlers, three scoped IAM policies (allow **and** deny), three READMEs, plus `common/` which enforces the pipeline order.
- `notifier/` — Slack payload with blast-radius context, conditional-write dedup, credential redaction.
- `tests/` — 185 tests. Per detection: pattern matches, pattern does *not* match the benign near-miss, handler acts correctly. Plus pipeline invariants and tests for the local pattern evaluator.
- `attack-sim/` — three Stratus scenarios, `assert.sh`, `measure.sh`. `sg-open` run four times (dry run, live, breaker); the other two written, **not run**.
- `docs/` — 15 ADRs in `architecture.md`, threat model with a suppression register, MITRE mapping with deliberate gaps, and **`docs/session-report.md`, which is the thing to read before doing anything with AWS** (written 2026-07-29, before the apply — its state tables are that day's, its procedures still current).
- `docs/evidence/` — four artefacts: pattern gate (17 agreements, zero disagreements), fixture capture, the `sg-open` detonation, time-to-remediate.
- Applied: the three Lambdas and their EventBridge targets exist in `awlz-lab`. The concurrency quota `L-B99A9384` that blocked the wiring was raised to 1000.
- Fifteen of the seventeen fixtures are recorded events from the lab.

Not done:

- **`s3-public` and `iam-key-leak` have never been detonated.** They are deployed and unit-tested, but no remediation of theirs has run against a real resource, so no latency is claimed for them.
- **Two fixtures are still documentation-derived** — the GuardDuty root-credential finding and the `sg-open` legacy-encoding benign case. Both marked, both explained in `tests/fixtures/README.md`, enforced by `tests/test_fixture_provenance.py`.
- **The false-positive rate is unknown.** Sixteen days live produced no new audit records, but an idle account generates no traffic to be wrong about. `docs/evidence/false-positive-review.md` is the outstanding artefact.
- No dead-man's-switch heartbeat (threat R3) — the largest gap in the threat model.
- No `ModifySecurityGroupRules` rule; `sg-open` has a documented blind spot.
- No T1098 detection (backdoor users / extra access keys) — largest coverage gap.

Next: the open items above, in the order `docs/PAChandoff.md` §4 gives them — the false-positive review is the one that gates letting this act outside the lab. Any *new* apply still follows section 4 of `docs/session-report.md`, and any account other than the lab starts at `dry_run = true` and stays there until a week of real traffic has been reviewed.

## Decisions already made — do not relitigate

Full reasoning in `docs/architecture.md` (ADR-001 … ADR-015). The ones most likely to be second-guessed:

| Decision | Rationale |
|---|---|
| Detections are code with tests, not console clicks | The entire premise. A detection with no test silently stops matching when AWS changes an event schema. |
| Patterns are **coarse**; the handler reads the resource back and decides | A pattern cannot evaluate a port range or parse a policy. `sg-open` is delivered 443-to-the-world and deliberately ignores it — that path is tested. |
| Every detection ships a fixture test **and a negative one** | `scripts/check-detection-coverage.sh` fails if a pattern test has no `assert not matches`. A pattern tested only for what it catches matches everything, forever, silently. |
| Snapshot to the audit table **before** any change, in two writes | Auto-remediation must not destroy IR evidence. A function killed mid-remediation leaves a `PLANNED` item, which is queryable. |
| One execution role per detection, **with explicit denies** | The deny list is the point: `sg-open` cannot `Authorize*` anything, `iam-key-leak` cannot `CreateAccessKey` or `PassRole`, `s3-public` cannot read an object. |
| Access keys **deactivated, never deleted** — enforced by an IAM `Deny` | Deletion destroys the `last-used` forensic trail. It is a policy statement, not a convention the handler has to remember. |
| Root and **temporary** credentials escalate, never remediate | An automation role that can disable root is a bigger problem than the finding. `UpdateAccessKey` cannot touch a session credential at all. `Status.ESCALATED` exists for this. |
| `s3-public` never deletes the bucket policy | BPA already neutralises it. Deleting destroys both intent and evidence. |
| `s3-public` treats a **conditioned** wildcard policy as safe | `Principal: "*"` + `aws:PrincipalOrgID` is normal. Remediating it is threat R2 with our own false positive as the attacker. |
| `sg-open` revokes only the world-open CIDRs, keeping the rest of the entry | A rule allowing `10.0.0.0/8` and `0.0.0.0/0` on 22 must keep the first. |
| Dry-run default; malformed config stays dry | Missing or malformed env vars must never be the reason production starts changing. |
| Circuit breaker in DynamoDB **and** Lambda reserved concurrency | They fail differently. The breaker counts dry-run attempts too — that is the signal you want before enabling remediation. |
| One deployment artifact, three handler entrypoints | Isolation comes from IAM, not from the artifact boundary. Needs `make build` before plan/apply. |
| One KMS CMK for the whole stack | USD 1/month each against a USD 20/month budget, for components that share a failure domain. |
| Lambdas not in a VPC | NAT is USD 32/month, more than the whole budget, against a path the function never takes. Suppression is inline with this reasoning. |
| `trivy config` instead of `tfsec` | tfsec is end-of-life; Aqua folded it into Trivy. |
| Isolated lab account only for detonation | `make attack` confirms the account ID; `assert.sh` refuses unless `STRATUS_LAB_ACCOUNT_ID` matches the caller identity. |

## Conventions

- A detection is a unit: pattern + metadata + handler + scoped policy + README + fixtures + tests for the match **and** the near-miss. Never merge a partial one — CI won't let you.
- Detection ID is kebab (`s3-public`) everywhere; the Python package is the snake form (`s3_public`). Mechanical, recorded in `metadata.yaml`, enforced by the coverage script.
- Handlers implement `plan()` and `apply()` only. They never call the audit log, the circuit breaker, or the notifier — `remediations/common/runtime.py` does, in a fixed order, so a handler cannot get it wrong.
- `plan()` returning `None` is the benign case and is normal, not an error. An empty `intended_actions` means "escalate, do not automate".
- Alerts carry context — principal, source IP, resource, blast radius — and never credential material. Access key *IDs* are kept; they are identifiers, not secrets.
- Python: `ruff` + `ruff format` + `mypy --strict`, `pytest` with `moto`. No live AWS in unit tests, ever. No runtime dependencies beyond the standard library and the runtime's own boto3.
- Terraform in `infra/`: pinned versions, `allowed_account_ids`, gitignored `terraform.tfvars`, partial S3 backend. Every scanner suppression carries an inline justification and a row in the threat model's suppression register.
- Fixtures carry a `_pac_fixture` provenance marker. Promoting one to `verified` requires updating the detection's `metadata.yaml` too, or the tests fail.
- Docs are part of the deliverable. A new detection updates the README table, `docs/mitre-attack.md`, and `docs/threat-model.md` in the same commit.
- Commits: Conventional Commits, author `heavensnipe@gmail.com`.

## Environment gotchas

Windows 11, PowerShell 7:

- PowerShell `&&` short-circuits — chained checks stop at the first failure and the rest silently never run.
- **Nothing is on `PATH` by default.** In a fresh shell:
  - Python scripts (`ruff`, `mypy`, `pytest`, `checkov`): `C:\Users\Pedro\AppData\Local\Python\pythoncore-3.14-64\Scripts`. `python -m ruff` / `python -m checkov.main` always work.
  - `terraform`, `tflint`, `trivy`, `shellcheck`: under `C:\Users\Pedro\AppData\Local\Microsoft\WinGet\Packages\<Vendor>.<Tool>_*\`. There are no shims in `WinGet\Links`.
  - The Bash tool has a narrower `PATH` than PowerShell; use PowerShell for tools, Bash for `.sh` scripts.
- `terraform -chdir=$var` does not expand the variable in PowerShell. Use a literal, or `Set-Location`.
- The PowerShell tool's working directory persists between calls — a `Set-Location infra` followed later by another `Set-Location infra` fails. Use absolute paths.
- Makefiles assume a POSIX shell. Run them from Git Bash or WSL.
- Installed: terraform 1.15.8, tflint 0.64.0 (+aws ruleset 0.44.0), trivy 0.72.0, checkov 3.3.8, shellcheck, aws-cli 2.36.9, Python 3.14. Local Python is 3.14; CI and the Lambda runtime are 3.13.
- AWS auth is IAM Identity Center SSO, profile `mgmt`, region `sa-east-1`. Sessions expire after 12 hours; log out explicitly when the work is finished. **Never introduce a static access key.**

## Sibling repos

Under `C:\Users\Pedro\Documents\Coding\`: `AwLZ` (provides the org, accounts, org trail, and GuardDuty this repo depends on), `KateClusters`, `ProvenancePipeline`.

## Working style the user expects

- Terse. No preamble, no restating the question. Fragments are fine.
- Anything that detonates a real attack technique, or that auto-modifies AWS resources, gets a clear warning and an explicit confirmation — never compressed into a fragment.
- Verify before claiming: run `pytest` and the linters rather than asserting the code is fine.
- When a recommendation turns out wrong, correct it in one line and move on.
- Say what is half-done. An unverified assumption presented as fact is worse than an admitted gap.
