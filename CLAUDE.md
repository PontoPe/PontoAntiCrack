# PontoAntiCrack (PAC) — context for Claude Code

Read this before touching anything. It is the handoff between sessions.

## What this is

Detection-as-code and automated remediation for AWS: CloudTrail → EventBridge → Lambda, with every detection written as tested code and validated by detonating the real attack technique against an isolated lab account.

Named after VAC — anti-cheat for cloud accounts. The game keeps running; the cheater gets caught and kicked automatically.

This is the repo that moves the owner from "sysadmin who knows security" to "security engineer". The differentiator is not that detections exist — it is that they have **unit tests on recorded CloudTrail events** and were **proven by attacking the account**, with time-to-remediate measured.

Owner: Pedro (GitHub `PontoPe`). Repo: `github.com/PontoPe/PontoAntiCrack`, private until there is real content.

## Where things stand

Done:

- Scaffolding only. README with architecture diagram, detection table, threat model, `docs/threat-model.md`, `docs/architecture.md` (ADR skeleton), `Makefile`, `.github/workflows/ci.yml`, directory tree.
- **No detections, no Lambdas, no Terraform written yet.**

Blocked on [AwLZ](../AwLZ):

- The org trail this repo consumes is created there. AwLZ has an AWS Organization (all features, SCPs enabled) and IAM Identity Center configured, but **nothing applied yet** — no member accounts, no CloudTrail.
- The isolated lab account for attack detonation is an AwLZ member account.

Do not start building here until AwLZ reaches `modules/logging`. Anything written before that is guessing at the event source.

Order of work once unblocked:

1. `infra/` — Terraform skeleton: EventBridge rules, Lambda functions, per-detection execution roles, DynamoDB audit table. Reuses the AwLZ backend conventions.
2. `s3-public` — the simplest end-to-end path. Pattern → handler → fixture test → live detonation.
3. `iam-key-leak`, then `sg-open`.
4. Slack notifier with context and deduplication; webhook in Secrets Manager.
5. Dry-run mode and tag-based exclusions before anything runs unattended.
6. Stratus Red Team scenarios wired to assertions.
7. Time-to-remediate measurements per detection → `docs/evidence/`.
8. MITRE ATT&CK mapping table.
9. Demo GIF: detonate → Slack alert with context → resource remediated, timer visible.

## Decisions already made — do not relitigate

| Decision | Rationale |
|---|---|
| Detections are code with tests, not console clicks | The entire premise. A detection with no test silently stops matching when AWS changes an event schema. |
| Every detection ships a fixture-based unit test | CI blocks untested detections via `scripts/check-detection-coverage.sh`. |
| Live validation with Stratus Red Team / CloudGoat | Asserting a detection works without running the technique is exactly the gap this repo exists to close. |
| **Isolated lab account only** for detonation | `make attack` prints the account ID and requires confirmation. The live CI job is gated behind a manual-approval environment and never runs on fork PRs. |
| One execution role per detection, scoped to exact actions | A shared admin Lambda role is an escalation path, not a remediation. |
| Original resource state snapshotted **before** any change | Auto-remediation must not destroy incident-response evidence. Remediations are reversible from the audit table. |
| Access keys are **deactivated**, never deleted | Deletion destroys the `last-used` forensic trail. |
| Dry-run default outside prod, plus tag exclusions and a circuit breaker | Auto-remediation weaponized as DoS is a real risk (threat R2). |
| Resource prefix `pac-`, exclusion tag `pac:exclude` | Consistent naming; SCPs in AwLZ protect `pac-*` resources from deletion. |
| `trivy config` instead of `tfsec` | tfsec is end-of-life; Aqua folded it into Trivy. |

## Conventions

- A detection is a unit: EventBridge pattern + Lambda handler + fixture test + MITRE mapping. Never merge a partial one.
- Alerts carry context — principal, source IP, resource, blast radius — and never carry credential material.
- Python: `ruff` + `mypy`, `pytest` with `moto` for AWS calls. No live AWS in unit tests.
- Terraform in `infra/` follows AwLZ conventions: pinned versions, `allowed_account_ids` on the provider, gitignored `terraform.tfvars`.
- Docs are part of the deliverable. A new detection updates the README table and `docs/threat-model.md` in the same commit.
- Commits: Conventional Commits, author `heavensnipe@gmail.com`.

## Environment gotchas

Windows 11, PowerShell 7:

- PowerShell `&&` short-circuits — chained checks stop at the first failure and the rest silently never run.
- `checkov` is installed but its Scripts directory may not be on `PATH`: `C:\Users\Pedro\AppData\Local\Python\pythoncore-3.14-64\Scripts`. `python -m checkov` always works.
- `terraform` lives under `C:\Users\Pedro\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_...\`. A shell opened before the install will not have it on `PATH`.
- `terraform -chdir=$var` does not expand the variable in PowerShell. Use `Set-Location`.
- Makefiles here assume a POSIX shell. Run them from Git Bash or WSL.
- Installed: terraform 1.15.8, tflint 0.64.0, trivy 0.72.0, checkov 3.3.8, aws-cli 2.36.9, Python 3.14.
- AWS auth is IAM Identity Center SSO, profile `mgmt`, region `sa-east-1`. Sessions expire after 1 hour — `aws sso login --profile mgmt` again is routine. **Never introduce a static access key.**

## Sibling repos

Under `C:\Users\Pedro\Documents\Coding\`: `AwLZ` (provides the org, accounts, and trail this repo depends on), `KateClusters`, `ProvenancePipeline`.

## Working style the user expects

- Terse. No preamble, no restating the question. Fragments are fine.
- Anything that detonates a real attack technique, or that auto-modifies AWS resources, gets a clear warning and an explicit confirmation — never compressed into a fragment.
- Verify before claiming: run `pytest` and the linters rather than asserting the code is fine.
- When a recommendation turns out wrong, correct it in one line and move on.
