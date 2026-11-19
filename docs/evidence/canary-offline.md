# Canary and eligibility guardrails — offline evidence

Executed 2026-11-18 UTC (2026-11-17 in Brazil). Baseline:
`6338628d422e0c443362ce65e44b3a67f8706061`. Raw command output and exit
codes: [canary-offline.json](canary-offline.json). This report describes the
working-tree increment, not the historical deployment.

## Executed gates

- Python 3.13.15: **238 tests passed** in 13.45 seconds. Moto and synthetic
  deliveries only; no live AWS in unit tests.
- Ruff check and format check: passed. Mypy strict: 26 source files, passed.
- Build and detection coverage: passed. All 26 staged files are Python source,
  byte-identical to their source paths; no cache, credentials or env files.
- ShellCheck 0.9.0: scripts, attack-sim scripts and secret hook passed.
- Terraform 1.17.2: recursive format check, backend-disabled init and validate
  passed. **No Terraform plan or apply was run.**
- TFLint 0.66.0: plugin init and recursive checks passed; AWS ruleset 0.44.0.
- Trivy 0.73.0: zero HIGH/CRITICAL findings, cached checks with updates and
  telemetry disabled. Variable values are deliberately absent; the scanner
  warns about this. Static analysis is not runtime IAM proof.
- Checkov 3.2.459: 99 passed, zero failed, nine justified suppressions; download
  and upload disabled. Suppressions remain documented in the threat model.
- IaC scanners used a source-only copy, byte-matched to every current `.tf`
  file; no state/tfvars/credentials were supplied.

## Behaviors exercised

Real-event producer implementation, durable pre-mutation claim, sequential
replay refusal, conditional-claim loss, snapshot-write failure, second-inspection
failure, authorization failure and post-authorization ledger-close failure.
A retained claim prevents another authorization even when the group has already
changed but the ledger still says `PLANNED`.

Controlled-clock observer tests distinguish correlated state correction from
mere invocation, dry run, missing evidence, wrong identity/target/request/action,
invalid timestamps, old slots and unresolved correlated attempts. Pagination is
exercised: a later-page unresolved record prevents a false healthy metric.
The simulated complete protocol covers both dry-run and actual moto correction.
Existing replay/concurrency/failure-safety tests are retained, not replaced.

An independent read-only reviewer inspected the implementation and reran the
233-test suite before the five additional failure-boundary cases were added.
No concrete blocker was reported within the dedicated unattached lab-SG boundary.
This review is not deployment approval or proof of service IAM enforcement.

## Secret-scan regression found by CI

The first PR run passed Terraform analysis but its full-tree Gitleaks gate
flagged the historical all-zero/all-X Slack webhook in
`tests/notifier/test_slack.py:17`. It is a mock, not an exposed credential.
`.gitleaks.toml` retains all default rules and exempts only that exact match
AND that exact test path, for the Slack rule only. Full-history scanning then
passed (43 commits). A negative control with a different mock team identifier
still failed with exit 1; the rule was not disabled or broadly path-excluded.
CI must be rerun on the amended head; the initial failure is not hidden.

## Live boundary — blocked, not passed

Official CLI STS on the available lab-named profile still identifies the
organization management account, not the approved lab. No AWS mutation,
new detonation, event-delivery test, alarm/resolve test, cleanup or incremental
cost measurement was performed. No static credentials were created or read.

A correct lab session, independently confirmed alias/region, existing PAC
backend/state, inventory, reviewed deployment plan and measurable USD 10 round
budget are still required. The changed scoped SG entrypoint and IAM are a
**breaking, fail-closed migration**; do not apply blindly to the historical
stack. Follow the [runbook](../runbooks/canary.md) for live acceptance and cleanup.
No exactly-once, serializability or account-outage survival guarantee is made.
The July 5.97-second result is historical and is not a measurement of this code.
