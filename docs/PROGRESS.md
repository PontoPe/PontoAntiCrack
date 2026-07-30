# PAC apply and EventBridge pattern gate

Updated: 2026-07-30

## Current step

B1/B2 stopped at the mandatory Terraform plan review. A saved plan was
generated, but no PAC resources were applied and no attack technique was
detonated.

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

## Observed

- Working tree was clean on `main` at re-entry.
- Only the `mgmt` IAM Identity Center profile is configured locally.
- AwLZ documents `OrganizationAccountAccessRole` as the management-to-member
  assume-role path.
- The live organization trail is logging and had delivered within 24 hours.
- The live GuardDuty detector in `awlz-lab` is enabled.
- `build/lambda/` contains `remediations/` and `notifier/`; it contains no
  `__pycache__`, Markdown, or `policy.json`.
- All local gates passed; `pytest` reported 167 passing tests.
- The plan is 43 additions, zero changes, zero destroys. It has three
  independent roles, three rules and targets, three functions, nine alarms,
  one KMS key, one empty Secrets Manager secret, and audit-table deletion
  protection. `dry_run` is `true`, `PAC_DRY_RUN` is wired to that guarded
  variable, and no `secret_string` or secret version appears.
- **Hard stop:** the plan's detection-specific IAM policies contain allowed
  reads that the current handlers never call:
  - `iam-key-leak`: `iam:GetUser`
  - `s3-public`: `s3:GetBucketLocation`,
    `s3:GetBucketPolicyStatus`
  - `sg-open`: `ec2:DescribeSecurityGroupRules`, `ec2:DescribeTags`

This violates the least-privilege plan gate in prompt 08. The plan was not
applied, and the authoritative EventBridge pattern checks were therefore not
run.

## TODO

1. Remove the five unused IAM reads, or document and implement the code path
   that requires each one.
2. Add a regression check that maps each allowed detection action to a handler
   call so least privilege cannot drift silently.
3. Re-run every local gate and generate a fresh saved plan.
4. Re-review all mandatory plan assertions.
5. Obtain explicit operator confirmation before applying the reviewed plan.
6. After apply, run AWS's authoritative evaluator for one positive and one
   near-miss event per pattern, capture raw evidence, update the handoff and
   threat model, commit, and push.
