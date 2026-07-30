# PAC apply and EventBridge pattern gate

Updated: 2026-07-30

## Current step

B1/B2 is paused after a successful second Terraform plan review. The saved
`infra/tfplan` is ready for an operator decision. No PAC resources were applied
and no attack technique was detonated.

## Commands attempted

- Read `AGENTS.md`, `docs/PAChandoff.md`, `docs/session-report.md` section 4,
  `docs/threat-model.md`, and the TrustStack prompt.
- `git status --short --branch`
- `git log --oneline -10`
- `aws configure list-profiles`
- Inspected the PAC provider guard, ignored variable-file convention, and the
  documented AwLZ member-account role path.
- Verified the live management caller, assumed
  `OrganizationAccountAccessRole` into `awlz-lab`, and made read-only
  CloudTrail and GuardDuty prerequisite calls.
- `make build`
- `ruff check`, `ruff format --check`, `mypy`, `pytest`, the detection coverage
  guard, `terraform fmt`, `terraform validate`, `tflint`, `trivy`, `checkov`,
  and `shellcheck`
- Configured a local-only `pac-lab` role profile sourced from the existing
  `mgmt` IAM Identity Center profile. No static credential was created.
- Created ignored `infra/terraform.tfvars` and `infra/backend.hcl`.
- `terraform init -reconfigure -backend-config=backend.hcl`
- `terraform plan -out=tfplan`
- Inspected the saved plan as JSON for action type, resource cardinality,
  dry-run wiring, secret handling, deletion protection, and detection-specific
  IAM actions.
- Continued from commit `b411565`.
- Removed the five unused detection-policy reads identified by the first plan
  review.
- Added `tests/test_policy_least_privilege.py`, which parses each handler's AST
  and requires exact equality between its AWS SDK calls and the policy's
  `Allow` actions.
- Re-ran `make build` and every local gate.
- Replaced the previous ignored `infra/tfplan` with a newly generated plan
  after reconfirming the `pac-lab` caller and the local dry-run inputs.
- Re-inspected the new saved plan as JSON, including detection and runtime IAM
  actions, resource references, managed-policy attachments, tags, secret
  resources, and all planned action types.

## Observed

- Working tree was clean on `main` at re-entry.
- Only the `mgmt` IAM Identity Center profile is configured locally.
- AwLZ documents `OrganizationAccountAccessRole` as the management-to-member
  assume-role path.
- The live organization trail is logging and had delivered within 24 hours.
- The live GuardDuty detector in `awlz-lab` is enabled.
- `build/lambda/` contains `remediations/` and `notifier/`; it contains no
  `__pycache__`, Markdown, or `policy.json`.
- All local gates passed; `pytest` reported 170 passing tests.
- The plan is 43 additions, zero changes, zero destroys. It has three
  independent roles, three rules and targets, three functions, nine alarms,
  one KMS key, one empty Secrets Manager secret, and audit-table deletion
  protection. `dry_run` is `true`, `PAC_DRY_RUN` is wired to that guarded
  variable, and no `secret_string` or secret version appears.
- Detection-specific IAM now contains only handler calls:
  - `iam-key-leak`: four allowed actions and 15 explicit denies
  - `s3-public`: six allowed actions and 12 explicit denies
  - `sg-open`: three allowed actions and eight explicit denies
- Runtime IAM remains restricted to the function's own log group, audit table,
  webhook-secret ARN, stack KMS key, and detection DLQ. There are no managed
  policy attachments.
- All tagged resources remain pinned to `Env = "lab"`.
- The old saved plan was replaced, not applied. The authoritative EventBridge
  pattern checks have not run.

## TODO

1. Obtain explicit operator confirmation before applying the reviewed saved
   plan.
2. After apply, run AWS's authoritative evaluator for one positive and one
   near-miss event per pattern, capture raw evidence, update the handoff and
   threat model, commit, and push.
