# Architecture — Ponto Anti-Crack

The high-level diagram lives in the [README](../README.md). This file records
**why**, not what.

## Shape

```
CloudTrail / GuardDuty
        │
        ▼
EventBridge rule            detections/<id>/pattern.json
        │                   coarse: cheap to evaluate, no state
        ▼
Lambda (one role per        remediations/<pkg>/handler.py
detection)                  precise: reads the resource back
        │
        ├── plan()          read-only. None means benign.
        ├── audit.open()    ◄── snapshot lands here, before anything changes
        ├── breaker         ◄── refuses after N actions per window
        ├── dry-run gate
        ├── apply()         the only method allowed to mutate
        ├── audit.close()
        └── notify()        Slack, deduplicated, credential-free
```

The ordering above is enforced in `remediations/common/runtime.py`. Handlers do
not call `audit.open`, the breaker, or the notifier — they cannot get the order
wrong because they never see it.

## Decisions

Each decision: context, options, choice, consequence. Append, never rewrite.

### ADR-001 — A detection is code with a test, not a console rule

- **Status:** accepted
- **Context:** The differentiator this repository exists to demonstrate is not
  that detections exist — anyone can enable GuardDuty — but that they are
  reviewable, testable artefacts.
- **Options:** (a) console/Security Hub rules; (b) Terraform-only EventBridge
  rules; (c) pattern + handler + fixture test as one reviewable unit.
- **Decision:** (c). `scripts/check-detection-coverage.sh` refuses a partial one.
- **Consequences:** More work per detection. In exchange, an AWS event-schema
  change breaks a test rather than silently breaking a detection — which is
  threat R4, and is the failure mode that makes console rules untrustworthy.

### ADR-002 — Coarse pattern, precise handler

- **Status:** accepted
- **Context:** EventBridge patterns cannot evaluate port ranges, parse a policy
  document, or read the resulting state of a resource. `PutBucketPolicy` that
  opens a bucket and `PutBucketPolicy` that closes one are the same event name.
- **Options:** (a) encode everything in the pattern, accepting false negatives;
  (b) match broadly and decide in the handler; (c) match broadly and remediate
  unconditionally.
- **Decision:** (b). The pattern is a cheap filter; the handler reads the
  resource back and returns `None` when the state turns out to be fine.
- **Consequences:** More invocations, all of them cheap. `sg-open` is delivered
  a rule opening 443 to the world and deliberately does nothing with it. The
  "benign" path is therefore a first-class, tested outcome rather than an error
  case — see `test_https_open_to_the_world_produces_no_plan`.

### ADR-003 — Snapshot before change, in two writes

- **Status:** accepted
- **Context:** Auto-remediation that destroys the pre-change state destroys the
  incident response with it (threat R6).
- **Options:** (a) one audit write after the fact; (b) write the snapshot first,
  update with the outcome afterwards; (c) snapshot to S3.
- **Decision:** (b). `AuditLog.open()` persists the snapshot, `AuditLog.close()`
  records the outcome, and the handler's `apply()` runs between them.
- **Consequences:** Two DynamoDB writes per remediation instead of one — free at
  this volume. If the function is killed mid-remediation, the item is left in
  `PLANNED`, which is queryable and is exactly the state you want to be able to
  find. `PLANNED` is deliberately not a member of `Status`.

### ADR-004 — One execution role per detection, with explicit denies

- **Status:** accepted
- **Context:** Threat R1. A Lambda role holding write access to production
  resources is an escalation target, and a role shared across three detections
  is the union of three attack surfaces.
- **Options:** (a) one shared role; (b) one role per detection with allow-only
  policies; (c) one role per detection with allow **and** deny statements.
- **Decision:** (c). The deny list is the interesting half:
  - `s3-public` cannot read an object, delete a bucket, or write a bucket policy.
  - `sg-open` cannot `Authorize*` anything, create or delete a group, or run an
    instance. It can close ports. That is all.
  - `iam-key-leak` cannot `DeleteAccessKey`, `CreateAccessKey`,
    `AttachUserPolicy`, `PassRole`, or `AssumeRole` — the standard IAM
    escalation primitives.
- **Consequences:** Three roles to review instead of one. The deny on
  `iam:DeleteAccessKey` means ADR-009 is enforced by IAM, not by the handler
  remembering it.

### ADR-005 — One deployment artifact, three handlers

- **Status:** accepted
- **Context:** Each Lambda needs `remediations/common` and `notifier`.
- **Options:** (a) a zip per detection, vendoring the shared code three times;
  (b) a Lambda layer; (c) one zip, three `handler` entrypoints.
- **Decision:** (c). `scripts/build-lambda.sh` stages `build/lambda`,
  `data.archive_file` zips it, and the three functions differ only in
  `handler = remediations.<pkg>.handler.lambda_handler`.
- **Consequences:** Requires `make build` before `plan`/`apply`, which is in the
  Makefile and in CI. In exchange the code that runs is provably the code that
  was tested, for all three at once. Isolation between detections comes from the
  IAM role, not from the artifact boundary — a shared zip shares no permissions.

### ADR-006 — boto3 is `Any` at the client seam

- **Status:** accepted
- **Context:** `mypy --strict` over code that calls boto3, which ships no type
  information in the Lambda runtime.
- **Options:** (a) `boto3-stubs` in CI; (b) `Any` at the seam; (c) drop strict.
- **Decision:** (b). `AwsClients` returns `Any`; everything above it is strictly
  typed.
- **Consequences:** No type checking of API call shapes — that is what the
  `moto`-backed tests are for. (a) was rejected because it type-checks a
  different boto3 than the runtime executes, which is a false sense of safety
  rather than an absent one.

### ADR-007 — Dry-run is the default and opting out is explicit

- **Status:** accepted
- **Context:** The setting that lets this system modify production resources
  must never be reached by accident.
- **Decision:** `Config.from_env` defaults `PAC_DRY_RUN` to `true`; a missing,
  empty, or malformed value stays true, and a malformed value raises rather than
  being coerced. `var.dry_run` defaults to `true` in Terraform.
- **Consequences:** Deploying and forgetting to configure it yields a system
  that watches, snapshots, and alerts, and changes nothing. That is the correct
  failure direction.

### ADR-008 — Circuit breaker in DynamoDB, concurrency cap in Lambda

- **Status:** accepted
- **Context:** Threat R2 — an attacker who can trigger a detection at will turns
  auto-remediation into a denial of service.
- **Options:** (a) reserved concurrency only; (b) a counter in the audit table;
  (c) both.
- **Decision:** (c), because they fail differently. Reserved concurrency bounds
  how fast we can be invoked; the DynamoDB counter bounds how much damage a
  storm is allowed to do, per detection, per rolling window. The counter
  increments in dry-run too — a dry-run deployment that would have tripped the
  breaker is precisely the signal you want before turning remediation on.
- **Consequences:** An open breaker is a `BLOCKED` outcome with a `critical`
  alert, not a silent stop.

### ADR-009 — Deactivate credentials, never delete; escalate root

- **Status:** accepted
- **Context:** `DeleteAccessKey` removes `GetAccessKeyLastUsed` with it, and
  that record is frequently the only evidence of what an attacker reached.
- **Decision:** `UpdateAccessKey Status=Inactive`, always. Root credentials and
  temporary session credentials are never acted on: the handler returns a plan
  with **no intended actions**, which the runtime turns into an `ESCALATED`
  outcome — snapshot written, critical alert sent, nothing changed.
- **Consequences:** `ESCALATED` exists as a first-class status precisely so that
  "this is real and a human has to do it" is not expressed as a silent skip. An
  automation role that can disable root is a larger problem than any finding it
  would be responding to.

### ADR-010 — The pattern evaluator in `tests/support` is a reimplementation

- **Status:** accepted, with a known limitation
- **Context:** Evaluating an event pattern authoritatively means calling
  `aws events test-event-pattern`. Unit tests here make no AWS calls.
- **Options:** (a) call AWS in tests; (b) assert on the pattern's JSON structure
  only; (c) implement the subset of the pattern language in use.
- **Decision:** (c), and it raises `UnsupportedPatternError` on anything outside
  that subset rather than guessing.
- **Consequences:** **These tests prove the pattern says what its author meant.
  They do not prove EventBridge agrees.** Confirming that is one
  `test-event-pattern` call per pattern against the real service, and it is on
  the post-apply checklist. The evaluator has its own test file for the same
  reason the detections do — a bug in it turns every detection test green for
  the wrong reason.

### ADR-011 — Kebab detection ID, snake Python package

- **Status:** accepted
- **Context:** `s3-public` is the ID in alerts, IAM, Terraform, and directory
  names. Python cannot import a hyphenated package.
- **Decision:** ID is kebab everywhere except the Python package, which is the
  same string with underscores. `detections/s3-public/metadata.yaml` records the
  mapping and the coverage script enforces it.
- **Consequences:** One mechanical translation, in one documented place.

### ADR-012 — One customer-managed KMS key for the whole stack

- **Status:** accepted
- **Context:** The audit table, the webhook secret, the dead-letter queues, and
  the function log groups all want encryption under a key we control. A CMK is
  USD 1/month and the budget for this repository is USD 20/month shared with
  [AwLZ](../../AwLZ).
- **Decision:** One key, four consumers.
- **Consequences:** No cryptographic separation between components that are
  already operated together and compromised together. Splitting them would buy
  separation between things that share a failure domain anyway.

### ADR-013 — Fixture provenance is machine-checked

- **Status:** accepted
- **Context:** This repository's central claim is "detections are tested against
  recorded CloudTrail events". Today that is false — every fixture was written
  from AWS documentation. A claim that is false and undetectable is worse than
  one that is false and marked.
- **Decision:** Every fixture carries a `_pac_fixture` marker; every detection's
  `metadata.yaml` carries `fixture_verified_against_live_event`;
  `tests/test_fixture_provenance.py` fails if the two disagree, if a marker is
  missing, or if an unverified fixture does not say how to capture the real one.
- **Consequences:** Promoting a fixture requires updating both places or CI
  fails. The honest version of the claim, until then, is "tested against the
  documented event schema".

### ADR-014 — Alert deduplication is a conditional write, not a TTL

- **Status:** accepted
- **Context:** DynamoDB TTL deletes expired items on its own schedule, typically
  within 48 hours. A 15-minute dedup window implemented with TTL would suppress
  alerts for the rest of the day.
- **Decision:** `attribute_not_exists(pk) OR expires_at < :now` on the put. The
  TTL attribute is garbage collection only.
- **Consequences:** Correct window semantics, and atomicity for free — two
  concurrent invocations cannot both decide they are first.

### ADR-015 — The remediation functions are not in a VPC

- **Status:** accepted
- **Context:** checkov CKV_AWS_117 flags this on every Lambda.
- **Decision:** No VPC. The functions call public AWS service endpoints and the
  Slack webhook, and reach no private resource.
- **Consequences:** A VPC would require a NAT gateway (~USD 32/month, more than
  the entire budget) or five interface endpoints (~USD 36/month), to protect
  against a lateral-movement path into a VPC the function never touches. The
  suppression is inline in `infra/modules/detection/main.tf` with this reasoning.
  Revisit if a remediation ever needs a private resource.

## Component detail

| Component | Responsibility | Notes |
|---|---|---|
| `detections/<id>/pattern.json` | Cheap filter on the event stream | Coarse by design (ADR-002) |
| `detections/<id>/metadata.yaml` | ATT&CK mapping, severity, fixture provenance | Read by the provenance tests |
| `remediations/common/runtime.py` | Enforces the pipeline order | The security property is the order |
| `remediations/common/audit.py` | Two-phase write to the audit table | ADR-003 |
| `remediations/common/redact.py` | Key-name and value redaction | Access key *IDs* are kept — they are identifiers, not secrets |
| `remediations/<pkg>/handler.py` | `plan()` and `apply()` only | Never touches audit, breaker, or notifier |
| `remediations/<pkg>/policy.json` | The extra power this detection needs | Reviewable on its own; runtime perms are added by the module |
| `notifier/slack.py` | Context-rich, credential-free alerts | `build_payload` is pure and is what the tests assert on |
| `notifier/dedup.py` | Conditional-write suppression | ADR-014 |
| `infra/modules/detection` | One detection's rule, function, role, DLQ, alarms | The unit of isolation |
| `tests/support/eventbridge.py` | Local pattern evaluator | ADR-010 — a reimplementation, and marked as one |

## Open questions

- [ ] Does EventBridge accept `$or` nested the way `detections/sg-open/pattern.json`
      uses it? Written from documentation, unconfirmed against the service.
- [ ] Is the CloudTrail encoding for `AuthorizeSecurityGroupIngress` really
      `ipPermissions.items[].ipRanges.items[].cidrIp`? The whole `sg-open`
      pattern rests on it.
- [ ] Does CloudTrail name the event `DeleteBucketPublicAccessBlock` (as assumed)
      or `DeletePublicAccessBlock` (the API name)?
- [ ] `ModifySecurityGroupRules` can widen a rule to `0.0.0.0/0` without emitting
      `AuthorizeSecurityGroupIngress`. Needs its own rule and fixtures.
- [ ] No detection for T1098 Account Manipulation — backdoor users and extra
      access keys. Currently the largest coverage gap.
