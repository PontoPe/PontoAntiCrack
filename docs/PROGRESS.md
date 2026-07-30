# PAC live validation progress

Updated: 2026-07-30

## Current step

B1/B2 is blocked on the Lambda account quota. The partial state is reconciled
and stable, but the account rejected reserved concurrency `5` on each Lambda
because its regional concurrent-execution quota is `10` and Lambda requires at
least `10` unreserved executions. No attack technique was detonated. The saved
plan used for that partial apply is invalid and must not be reused.

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
- Committed the validated fix as `5deef0b` and pushed `main` to `origin`.
- Reconfirmed the lab caller and attempted
  `request-service-quota-increase` for `L-B99A9384 = 25`.
- Opened the official AWS Service Quotas console through an in-memory,
  temporary federated session to verify the API result. No credential or
  sign-in token was printed or persisted, and the console session was signed
  out after verification.
- Installed DataDog Stratus Red Team `v2.34.1` from the official GitHub release
  in Terraform's ignored local tool directory. Verified both release files
  against GitHub's asset digests and verified the archive against the official
  release checksum list before extraction.
- Executed `stratus status`; every listed technique was `COLD`.
- Compared the three live Lambdas with Terraform state and verified handler,
  runtime, role, code hash, memory, timeout, `PAC_DRY_RUN=true`, and
  `PAC_ENVIRONMENT=lab`.
- Removed the three Terraform `tainted` markers only after that comparison.
  This changed state metadata, not AWS resources, and prevents an unsafe
  replacement in the next plan.

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
- The Service Quotas API rejected `25` before creating a request:
  `You must provide a quota value greater than the default quota value of
  1000.0`. The official console independently showed applied value `10`,
  default value `1000`, and enforced a minimum request value of `1000`.
  Request ID: none. State: not submitted.
- The AWS Support API cannot provide an alternate request path because the
  account does not have a Premium Support subscription. No request for `1000`
  was attempted because the authorization is explicitly limited to `25`.
- Stratus release archive SHA-256:
  `ca73bb639216a21907b28d5791940c1cbce9f75dfa8913956c96a41112fa43ad`.
  Official checksum-file SHA-256:
  `ca174b514258dc5cc25f2d9fabc37c182040d2aafe47650cc231e8475ff55b75`.
- The three Lambda functions exist in Terraform state, but no EventBridge rule
  has a target. No apply, AWS CLI operation, Stratus process, or detonation is
  active.
- Terraform now tracks `31` managed resources: the three Lambdas are
  `Active/Successful`; three dead-letter alarms exist; the six other alarms,
  three Lambda permissions, and three EventBridge targets do not exist yet.
- Terraform state contains zero tainted instances after reconciliation.
- `reserved_concurrency = 5` is unchanged. Reducing or removing it would weaken
  ADR-008.
- The ignored `infra/tfplan` is stale after the partial apply and is not an
  authorized recovery artifact.

## Cleanup

- No attack resources were created.
- No EventBridge targets are active.
- `stratus status` is clean: all techniques are `COLD`.
- The temporary AWS console session was signed out.

## TODO

1. Obtain an AWS-supported path that accepts the exact applied-quota increase
   from `10` to `25`; the Service Quotas API and console currently reject it
   against the formal default of `1000`.
2. After `L-B99A9384` is actually at least `25`, reconfirm the caller and
   generate a new saved plan from the reconciled state.
3. Fully review that new plan. Do not reuse the stale plan or accept destroys,
   account changes, weaker concurrency, or unexpected targets.
