# PAC live validation progress

Updated: 2026-07-30

## Current step

B1/B2 is paused after a partial Terraform apply. The account accepted the PAC
resources but rejected reserved concurrency `5` on each Lambda because its
regional concurrent-execution quota is `10` and Lambda requires at least `10`
unreserved executions. No attack technique was detonated. The saved plan used
for that partial apply is invalid and must not be reused.

## Commands attempted

- Read the autonomous-owner prompt and all required PAC handoff documents.
- Reconfirmed `OrganizationAccountAccessRole` in account `<lab-account>`
  (`awlz-lab`) before each plan and apply.
- Revalidated the organization trail, GuardDuty, local build, tests, linters,
  Terraform validators, and infrastructure scanners.
- Applied only the reviewed saved dry-run plan. The first attempt exposed an
  AWS provider conflict between customer-managed KMS and the explicit
  SQS-managed-encryption flag.
- Removed the conflicting SQS flag while retaining
  `kms_master_key_id = var.kms_key_arn`.
- Added `tests/test_infra_invariants.py` to require customer-managed KMS and
  reject an active SQS-managed-encryption flag in the detection module.
- Generated and fully reviewed a recovery saved plan for the remaining
  resources, then applied only that saved plan.
- Inspected Terraform state, Lambda functions, EventBridge targets, running
  processes, and the live Lambda service quota after the apply stopped.
- Re-ran the complete local gate set after the fix:
  `build`, `ruff`, formatting, strict `mypy`, `pytest`, detection coverage,
  `shellcheck -x -S warning`, Terraform formatting/init/validation, `tflint`,
  Trivy, and Checkov.

## Observed

- The SQS correction is legitimate: AWS provider `6.57.1` rejects configuring
  `kms_master_key_id` together with `sqs_managed_sse_enabled`, even when the
  latter is `false`. Removing the redundant flag preserves the PAC CMK and
  does not weaken encryption.
- All local gates pass. `pytest` reports `171 passed`; Trivy reports zero
  HIGH/CRITICAL findings; Checkov reports `76 passed`, `0 failed`, `6 skipped`.
- The second apply stopped with
  `InvalidParameterValueException: Specified ReservedConcurrentExecutions for
  function decreases account's UnreservedConcurrentExecution below its
  minimum value of [10]`.
- Live quota `L-B99A9384` in `sa-east-1` is `10`, adjustable and regional.
- The three Lambda functions exist in Terraform state, but no EventBridge rule
  has a target. No apply, AWS CLI operation, Stratus process, or detonation is
  active.
- `reserved_concurrency = 5` is unchanged. Reducing or removing it would weaken
  ADR-008.
- The ignored `infra/tfplan` is stale after the partial apply and is not an
  authorized recovery artifact.

## Cleanup

- No attack resources were created.
- No EventBridge targets are active.
- Stratus was not installed at this checkpoint, so its independent status
  verification remains pending.

## TODO

1. Commit and push the validated SQS provider fix and regression test.
2. Request Lambda quota `L-B99A9384 = 25` only in `awlz-lab`,
   `sa-east-1`, and record the request ID and state.
3. Install Stratus from an official verified artifact and prove
   `stratus status` is clean without detonating a scenario.
4. Reconcile the partial Terraform state. If the quota is approved, generate
   and fully review a new saved plan from current state; do not reuse the stale
   plan or accept destroys, account changes, weaker concurrency, or unexpected
   targets.
