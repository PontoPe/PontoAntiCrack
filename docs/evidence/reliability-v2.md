# Reliability v2 — bounded offline increment

> Historical A0/A1 execution record. The subsequent A2 canary/scoped-guardrail
> work and restored static toolchain are recorded in
> [canary-offline.md](canary-offline.md). "Not done" below means at the end of
> this earlier execution, not the current source inventory.

## Scope and provenance

- Date: 2026-11-17. Baseline: `6338628d422e0c443362ce65e44b3a67f8706061`.
- Local, uncommitted increment for Blueprint A0/A1 only; **not a completed Blueprint A MVP**.
- Continued the interrupted working tree: `audit.py`, `sg_open/handler.py`, and
  `test_replay_concurrency.py` already contained the first replay fixes/tests.
  Those edits were inspected and preserved, not reset. The baseline was extracted
  with `git archive HEAD` into scratch to reproduce failures without touching them.
- Real execution output, command arguments, versions, timestamps, expected exit
  codes, and artifact checks: [reliability-v2-offline.json](reliability-v2-offline.json).
- Tests use moto resources and synthetic delivery interleavings/fault injection.
  Reusing a recorded fixture does **not** turn a simulated interleaving into an
  AWS observation. Existing fixture provenance markers were not promoted.
- No AWS APIs, credential files, `.env`, Terraform state, cloud resources, registry,
  shared services, commits, pushes, notifications, or live attacks were used.

## Demonstrated defects and corrections

| Case | Baseline / pre-fix result | Corrected contract |
|---|---|---|
| Same dry-run event delivered twice | Second audit write replaced the first snapshot | UUID-suffixed sort key per delivery; event time/ID retained for correlation |
| Two plans read the same unsafe group | Second revoke raised `InvalidPermission.NotFound` | Apply re-reads and intersects current state with snapshotted targets; already-absent targets need no mutation |
| Competitor wins after the pre-apply read | Runtime returned `FAILED` although target was absent | Handle only `InvalidPermission.NotFound`, and only if another read confirms all planned targets absent; return no attributed actions |
| Revoke returns success but changes nothing | Runtime returned `APPLIED` | Verify planned targets absent before returning; otherwise `FAILED` with reconciliation-required error |

The first two tests were reproduced red against an isolated baseline, whose
original suite passed (185 tests). The next two were run red before their
additional handler changes and then green. The raw record also replays the
focused defect tests against baseline. Other new tests characterize safety
invariants rather than claiming newly fixed defects.

No global lock or exactly-once claim was introduced. DynamoDB evidence and EC2
mutation are still separate operations. `APPLIED` with an empty action list
means this delivery observed its targets absent, not that it changed EC2.
The audit key remains `pk = AUDIT#<detection>#<resource>`; `sk` changes from
`<event_time>#<event_id>` to `<event_time>#<event_id>#<delivery_uuid>`.
Any external exact-sort-key lookup must use the stored key or a prefix query;
there was no external consumer migration or live-table migration in this work.

## Safety coverage

`tests/remediations/test_replay_concurrency.py` adds 12 collected cases:

- repeated dry-run preserves two different pre-change snapshots;
- two in-flight plans converge while keeping private SSH and public HTTPS;
- read/revoke race converges without claiming the competitor's action;
- successful API response without effect is not accepted;
- missing-permission, access-denied and throttling errors with targets still
  present remain failures (three parametrized cases);
- newly added IPv6 exposure is not silently added to an older IPv4 plan;
- an old/delayed event after correction is a no-op;
- deterministic nested invocations retain distinct snapshots and terminal actions;
- snapshot-open failure propagates before any EC2 mutation;
- audit-close failure after mutation preserves `PLANNED`; replay observes current
  safe state, writes a separate `SKIPPED` item, and never reopens access or
  overwrites the unresolved evidence.

The existing runtime was unchanged. Its dry-run, breaker, exclusions, and
snapshot-before-apply regressions remain part of the full suite. Failure-safety
injection at the audit open/close boundary proves ordering, not real DynamoDB
availability behavior.

## Executed offline gates

Run from the repository root with the existing manifest-backed `.venv`.
Clear the host's inherited `PYTHONPATH`: otherwise Python 3.14 Hermes packages
can shadow the project Python 3.13 environment (an initial Checkov import failed
this way; clearing it restored the project toolchain, with no install required).

```sh
env -u PYTHONPATH .venv/bin/python -m pytest tests/ -q
env -u PYTHONPATH .venv/bin/python -m pytest tests/remediations/test_replay_concurrency.py -q
env -u PYTHONPATH .venv/bin/python -m ruff check .
env -u PYTHONPATH .venv/bin/python -m ruff format --check .
env -u PYTHONPATH .venv/bin/python -m mypy remediations/ notifier/
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH= make build coverage
git diff --check
```

- Full suite: **197 passed** (185 baseline + 12 new cases).
- Ruff lint/format, strict mypy, build, detection coverage and whitespace gates passed.
- Built Lambda package: 22 files, source contents checked, no cache/secret/env files.
- Bash syntax checks passed for tracked shell scripts; this is **not ShellCheck**.
- Trivy offline: 0 HIGH/CRITICAL misconfigurations. Uses cached/bundled checks,
  no policy/version update or telemetry. Warns that `account_id` and
  `environment` values are unavailable; no real tfvars were loaded.
- Checkov offline Terraform scan: 76 passed, 0 failed, 6 existing skips;
  downloads, external module retrieval, and result upload disabled.
- Both IaC scans ran on the `git archive` baseline `infra/`, which is identical
  to current tracked `infra/` (no infrastructure changes in this increment).
- Gitleaks scans only the changed/new source and documentation passed to stdin,
  not private environment files or the whole working directory/history.
- Terraform, TFLint and ShellCheck are absent. Therefore `terraform fmt`,
  `terraform validate`, TFLint and ShellCheck are **not verified here**.
  `make lint` and `make validate` were not represented as passing aggregate gates;
  no tool/provider download or `terraform init` was attempted.

## Failure recognition and manual reconciliation

1. A `PLANNED` audit record is an unresolved attempt, **not proof that nothing
   changed**. An audit-close exception propagates so the invocation fails; no
   success notification is emitted by that path.
2. With separately authorized read-only access, inspect the current group and
   correlate every delivery by event ID, resource and recorded time. A subsequent
   `SKIPPED` only confirms that later inspection found no dangerous plan.
3. Preserve the original snapshot/status. Record human findings separately;
   do not relabel an earlier uncertain delivery automatically.
4. Replay may safely inspect/remediate the current resource, but does not close
   the original `PLANNED` record. No automatic reconciler/age alarm was added.
5. Never restore world-open ingress automatically from a snapshot. A snapshot
   is evidence; reopening access requires its own reviewed, authorized change.

## Remaining acceptance — not done

- **Offline follow-up:** A2 canary/observer contract, controlled-clock correlation
  tests, resource-eligibility/account-mismatch refusal tests, and any associated
  IAM/Terraform. No canary stub or deployable infrastructure was added here.
- Restore the missing static toolchain and run Terraform formatting/validation,
  TFLint and ShellCheck before cloud review. Re-run scanner gates with the
  reviewed lab configuration rather than treating unknown-variable scans as a plan.
- **AWS work requires separate explicit authorization** for lab account, region,
  resource allowlist and cost. Verify STS/account and existing state/inventory;
  do not recreate state, modify shared resources, or infer current health from
  July's documentation.
- Review resource eligibility in planning and IAM. Dedicated canary SG must have
  no ENI/instance attachment and must carry unmistakable lab tags/prefixes.
- Review the real plan, deploy dry-run, test patterns with EventBridge, inspect
  the audit snapshot and unchanged SG, and independently test alert delivery.
- Then exercise scoped IPv4/IPv6 revocation, delayed/repeated events and actual
  concurrent deliveries; inspect final rules and all audit items. Measure real
  read-after-write behavior, throttling, permission failures and partial failures.
- EC2 is eventually consistent: immediate verification can conservatively fail
  after a successful revoke. No bounded backoff was invented offline. Also, a
  removed/re-added identical tuple is not distinguished by rule identity; this
  does not provide serializability or protection against arbitrary concurrent
  operator/attacker edits. New exposures need new snapshots/events.
- Safely inject post-mutation audit failure in the lab; demonstrate operational
  detection and manual reconciliation of unresolved `PLANNED` items.
- Build and prove independent canary observation, deliberately interrupt only
  the sandbox path, observe alert delivery and resolution after restoration.
  Invocation alone is not proof of remediation; shared-account observability
  does not prove survival of total account loss.
- Cleanup only resources created by the authorized run; record residues, cost,
  latency and raw evidence. Do not remove an organizational trail or shared table.

July's **5.97 s** is retained as historical evidence in
[detonation-sg-open.md](detonation-sg-open.md), not reused as a new benchmark.
This increment establishes tested local replay/failure-safety behavior only.
