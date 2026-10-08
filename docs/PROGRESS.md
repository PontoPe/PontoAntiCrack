# PAC live validation progress

Updated: 2026-08-15, after a 16-day live-remediation observation window

## Current step

**B1 through B8 are done.** The repository is public (`github.com/PontoPe/PontoAntiCrack`,
last push 2026-08-15) and every step of the live-validation plan has run. What
remains is not part of this plan: detonating `s3-public` and `iam-key-leak`, the
false-positive review after a week of real traffic, and the R3 heartbeat.

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
- **The lab is left running with `dry_run = false`.** That is the state the
  measurement was taken in and the state the evidence describes. It lives in the
  gitignored `infra/terraform.tfvars`, so it is recorded here rather than being
  visible in the repository. Any account other than the lab starts at
  `dry_run = true` and stays there until a week of real traffic has been
  reviewed — step 10 of the handoff order.

## Live observation — 2026-08-15

The lab has run with `dry_run = false` since 2026-07-31. Sixteen days later the
audit table holds **the same ten records** it held at the end of that session:
one `SKIPPED`, one `DRY_RUN`, four `APPLIED`, four `BLOCKED`. Nothing after
`2026-07-31T00:08:56Z`.

That is the intended result and it is worth stating as evidence rather than
silence: **zero remediations and zero false positives in sixteen days of live
operation** against an account that is otherwise idle. It is not a
false-positive *rate* — an idle account generates no traffic to be wrong about,
and step 10 of the handoff order still calls for a week of real traffic before
this is read as one.

The five GuardDuty sample findings created on 2026-07-30 never reached a
detection: they predate the EventBridge targets by roughly an hour. They were
archived on 2026-08-15.

## Session log — B1, the apply (2026-07-30)

Everything from here to the CI section is the record of the apply session, kept
as history. Where it disagrees with **Current step** above, the section above
wins: the quota reached 1000, the recovery apply completed, the EventBridge
targets exist, and `sg-open` was detonated afterwards.

### Commands attempted

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

### Observed

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

### Cleanup, at the end of that session

- No attack resources were created.
- No EventBridge targets were active **yet** — they were created by the recovery
  apply after the quota landed.
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

B1 through B8 are done; the list below is what is left, and none of it is part
of that plan.

1. Detonate `s3-public` and `iam-key-leak` and assert, then measure their
   time-to-remediate. Only `sg-open` has a number.
2. Put a real value in the Slack webhook secret and prove alert delivery end to
   end. An absent webhook is still recorded as an undelivered alert, not a
   failed remediation, and the audit record remains the system of record.
3. `docs/evidence/false-positive-review.md` — a week of real traffic under
   `dry_run = true`, which is what gates letting this act outside the lab.
4. Dead-man's-switch heartbeat (threat R3): a scheduled canary through each rule
   plus an alarm with `treat_missing_data = "breaching"`. A deleted rule emits
   no metric, so nothing fires today.
