# PAC live validation progress

Updated: 2026-07-30, after B1 completion and notifier remediation

## Current step

**B1 through B7 are done. B8 — publication — is the only step left.**

- Quota `L-B99A9384` was requested at 1000, the lowest value Service Quotas
  accepts, and the applied value reached 1000. The deferred wiring then applied
  cleanly: 12 creates, 3 updates, no drift.
- `make patterns`: 17 fixtures, zero disagreements with EventBridge.
- Fifteen of seventeen fixtures are recorded events.
- `sg-open` was detonated four times with Stratus Red Team v2.34.1. Live
  remediation took **5.97 s** from the attacker's API call; the dry run before
  it changed nothing; the circuit breaker held after five actions and left four
  ports open with four `BLOCKED` records.
- Two defects were found by detonating that every green gate had missed: the
  loop guard read the caller-chosen session name, and the pattern knew only one
  of the two CloudTrail encodings of `AuthorizeSecurityGroupIngress`. Both
  fixed, both written up.
- The lab is clean: no technique `WARM` or `DETONATED`, no instances, no
  buckets, all three dead-letter queues empty.
- History was scrubbed of the lab account ID and force-pushed before
  publication; the only secret-shaped strings in the history are AWS
  documentation examples and placeholder webhooks.

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
- After the quota was applied at `1000`, completed the reviewed recovery apply.
  B1 is complete; the prior quota failure and partial state below are retained as
  history, not current state.
- Before any detonation, tested the notifier path with the absent Slack webhook
  value found in the lab. Fixed the post-remediation failure mode in `d1c4ab0`
  and added coverage for unreadable and non-HTTPS secret values.

## Observed

- The SQS correction is legitimate: AWS provider `6.57.1` rejects configuring
  `kms_master_key_id` together with `sqs_managed_sse_enabled`, even when the
  latter is `false`. Removing the redundant flag preserves the PAC CMK and
  does not weaken encryption.
- All local gates pass. `pytest` reports `171 passed`; Trivy reports zero
  HIGH/CRITICAL findings; Checkov reports `76 passed`, `0 failed`, `6 skipped`.
- Before the quota increase, the second apply stopped with
  `InvalidParameterValueException: Specified ReservedConcurrentExecutions for
  function decreases account's UnreservedConcurrentExecution below its
  minimum value of [10]`.
- Before the quota increase, live quota `L-B99A9384` in `sa-east-1` was `10`.
  The Service Quotas API rejected `25` before creating a request:
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
- The quota is now `1000` and B1's recovery apply completed. The previous
  no-target/31-resource description is superseded; verify the post-apply state
  immediately before B4 rather than relying on the partial-apply inventory.
- No Stratus process or detonation is active.
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

## CI

CI had been failing on every push and the cause was not the quota.
`check-detection-coverage.sh` and `build-lambda.sh` were committed mode 644, so
the runner exited 126 with "Permission denied" before any gate ran — the
negative-test gate had never actually executed in CI, only locally where
git-bash ignores the mode bit. `aquasecurity/trivy-action@0.28.0` had also
stopped resolving and is now pinned to the v0.36.0 SHA. CI is green as of
commit `e796ecf`.

## TODO

1. Before B4, reconfirm the lab caller, the completed Terraform state and that
   `PAC_DRY_RUN=true`; do not weaken `reserved_concurrency = 5`.
2. Detonate the approved Stratus technique in dry-run mode and assert the audit
   snapshot, Lambda invocation and unchanged resource. An absent Slack webhook
   must be recorded as an undelivered alert, not treated as a failed remediation.
3. Complete B5 and B6 only after B4: live lab remediation and timing, then a
   deliberate circuit-breaker trip.
4. Capture evidence and demo, then complete publication (B7–B8).
