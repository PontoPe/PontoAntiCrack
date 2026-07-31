# Handoff — PontoAntiCrack

Written 2026-07-29, current as of **2026-07-30**. Entry point for anyone — or
any session — picking this up cold.

If you read one other file after this one, read
[session-report.md](session-report.md) §3 and §4.

---

## 1. In sixty seconds

Detection-as-code for AWS. Three detections, each one a unit: an EventBridge
pattern, a Lambda handler, a scoped IAM policy, a README, fixtures, and tests
for both what it catches and what it must not catch.

The thing that makes this worth showing to anyone is not that the detections
exist. It is that they have tests, and that they will have been proven by
detonating the real technique.

**Current state: deployed, detonated, measured, and public.**

- The three Lambdas are deployed in `awlz-lab` and wired to EventBridge. The
  concurrency quota that blocked the wiring was raised to 1000, the lowest value
  Service Quotas accepts.
- `make patterns` replays all seventeen fixtures through
  `aws events test-event-pattern`: seventeen agreements, zero disagreements.
- Fifteen of seventeen fixtures are recorded events captured in the lab.
- `sg-open` was detonated with Stratus Red Team v2.34.1. Live remediation
  revoked the world-open SSH rule **5.97 s** after the attacker's API call and
  left the group's port 443 rule alone. The dry run before it changed nothing.
  The circuit breaker was tripped on purpose and held.
- Detonating found two defects that every green gate had missed: a loop guard
  reading the caller-chosen session name, and a pattern that knew only one of
  the two CloudTrail encodings of `AuthorizeSecurityGroupIngress`.
- The repository is public. History was scrubbed of the lab account ID first.
- `s3-public` and `iam-key-leak` have not been detonated, so their remediation
  latency is unmeasured.

Nothing about that is hidden — it is marked in the fixtures, in the detection
metadata, in the README, in the threat model, and enforced by a test that fails
if the markers stop being accurate.

---

## 2. What exists

| | Count | State |
|---|---|---|
| Detections | 3 | `s3-public`, `iam-key-leak`, `sg-open` |
| Terraform files | 14 | Root stack + one reusable `detection` module |
| Event fixtures | 17 | **15 captured from real events; 2 documentation-derived** |
| Tests | 185 | All passing |
| ADRs | 15 | `docs/architecture.md` |
| Detonations run | 4 | one technique: dry run, live, and a breaker run |
| Evidence artefacts | 4 | pattern gate, fixture capture, detonation, time-to-remediate |

### Verification, as of `c101ce8`

Run on Windows 11 / PowerShell 7 with the toolchain in §7:

```
pytest                          185 passed
ruff check                      All checks passed!
ruff format --check             54 files already formatted
mypy --strict                   Success: no issues found in 22 source files
terraform fmt -check -recursive clean
terraform validate              Success! The configuration is valid.
tflint --recursive              no issues
trivy config infra              0 misconfigurations, 0 suppressions
checkov -d infra                76 passed, 0 failed, 6 skipped
check-detection-coverage.sh     all detections complete
shellcheck -S warning           clean
make patterns                   17 fixtures, 0 disagreements with the service
```

Reproduce all of it with `make lint && make test && make coverage && make validate`
from Git Bash or WSL. The Makefile assumes a POSIX shell.

Dependency note, 2026-07-30: a clean `terraform init` found that locked AWS provider
`6.57.0` had disappeared from the official registry. `terraform init -upgrade` selected
the signed replacement `6.57.1`; the regenerated lock file and `terraform validate` are
green. The `~> 6.0` constraint did not change.

### Commits in this body of work

```
af6d5be docs: record ADRs, threat model, MITRE mapping, and session report
96b2586 ci: gate on formatting, tflint, shellcheck, and detection coverage
5c6bcba feat(attack-sim): add stratus scenarios and assertions, unexecuted
dbcc46f feat(infra): add terraform for rules, functions, per-detection roles, audit table
0ca9098 test: add fixture tests, pipeline invariant tests, and a provenance guard
d794d14 feat(notifier): add Slack alerting with context, dedup, and redaction
32f3f4c feat(remediations): add detection runtime and the three remediation handlers
2594d92 build: add python toolchain, lambda packaging, and detection coverage gate
```

---

## 3. What is proven, and what is only claimed

This distinction is the whole point of the repository, so it gets stated
plainly rather than implied.

### Proven by the 185 tests

- Each pattern matches the events its author intended.
- Each pattern **rejects** the plausible-but-benign near-miss: a read-only
  `GetBucketAcl`, an `AccessDenied` that changed nothing, SSH from
  `10.0.0.0/8`, a LOW-severity GuardDuty finding, a finding about an EC2
  instance rather than a key.
- The handlers make the right call against a `moto`-backed AWS. A wildcard
  bucket policy scoped by `aws:PrincipalOrgID` is left alone. 443-to-the-world
  is left alone. A rule allowing both `10.0.0.0/8` and `0.0.0.0/0` on port 22
  loses only the second. A root-credential finding is escalated, never acted on.
  An `AccessDenied` while inspecting propagates instead of being misread as
  "not public".
- The pipeline invariants hold: the snapshot survives a failed remediation,
  dry-run changes nothing, the circuit breaker stops a storm and counts dry-runs
  too, a self-triggered event is dropped, an alert never carries credential
  material.

### Proven against AWS on 2026-07-30

- **EventBridge agrees with every pattern on every fixture.** The local
  evaluator in `tests/support/eventbridge.py` and the service returned the same
  verdict fifteen times, which is what ADR-010 said was missing.
- **The fixtures are real events.** Fourteen were captured in `awlz-lab` from
  API calls against resources created and deleted in the same run. The
  assumption flagged as highest-risk held: CloudTrail emits
  `DeleteBucketPublicAccessBlock`, not the API's `DeletePublicAccessBlock`.
- Real events corrected five assumptions the tests around the patterns had
  encoded — principal shape, two GuardDuty `userType` values, one severity, and
  a benign call that turns out to come from Access Analyzer.
  `docs/evidence/fixture-capture.md` lists them.

### Not proven

1. **The root-credential fixture is documentation-derived**, so
   `detections/iam-key-leak/metadata.yaml` still says
   `fixture_verified_against_live_event: false`. No GuardDuty sample can be
   issued against the account root, and manufacturing a root compromise to
   capture one is not a reasonable trade.
2. **The captured GuardDuty findings are service-generated samples.** Type,
   severity and resource shape are exactly what the service emits — which is
   what the pattern reads — but no real compromise produced them.
3. **Nothing has been detonated.** No latency measured, no false-positive rate
   observed, no remediation has touched a real resource. This is blocked on the
   Lambda concurrency quota, not on work.

### The three assumptions that are load-bearing

Each would break an entire detection, and each is answered by a single
`aws events test-event-pattern` call:

| # | Assumption | Where | If wrong |
|---|---|---|---|
| 1 | EventBridge accepts `$or` in the position used | `detections/sg-open/pattern.json` | `create-rule` fails at apply, or the rule matches nothing. Fix: split into two rules, IPv4 and IPv6, same target |
| 2 | EC2 renders CloudTrail lists as `ipPermissions.items[].ipRanges.items[].cidrIp` | same file | `sg-open` matches nothing, silently |
| 3 | CloudTrail names the event `DeleteBucketPublicAccessBlock`, not `DeletePublicAccessBlock` (the API name) | `detections/s3-public/pattern.json` | That detection path is dead; pattern needs both names |

**This is step 3 of the apply order and it is not optional.** A `false` there
means the detection is dead regardless of how many unit tests pass.

`make patterns` runs all three patterns against all fifteen fixtures and fails
on the first disagreement with the service. It needs credentials and nothing
else — no Lambda, rule or completed apply — so it does not have to wait behind
the Lambda concurrency quota that currently blocks the wiring. Run it first.
`./scripts/verify-patterns.sh --list` resolves the fixtures without calling AWS.

---

## 4. Do this next, in this order

Condensed from [session-report.md](session-report.md) §4, which has the
verification detail for each step.

Steps 0 through 3 and step 6 are **done** as of 2026-07-30 and are kept here so
the order still reads straight. The next open step is 4.

| # | Step | State | Stop if |
|---|---|---|---|
| 0 | [AwLZ](../../AwLZ) applied through `modules/logging`; org trail delivering, GuardDuty on in the lab account | ✅ | It isn't — this repo consumes that trail |
| 1 | `make build` | ✅ | `build/lambda/` is missing `remediations/` or `notifier/` |
| 2 | `terraform plan` with `dry_run = true`, then apply | ⚠️ partial — three Lambdas exist, no EventBridge target does | The plan shows fewer than 3 IAM roles, or `PAC_DRY_RUN` is not `"true"`, or a `secret_string` appears on the secret |
| 3 | `make patterns` — all three patterns against all fifteen fixtures | ✅ 15/15 | **Any positive fixture returns `false`, or any `benign-*` returns `true`** |
| 6 | Capture the real events, replace the fixtures, flip the provenance markers, `make test` | ✅ 14 of 15 | — |
| — | **Lambda concurrency quota reaches 25** | ⏳ request for 1000 open as a support case | Service Quotas refuses; it will not accept a value below the formal default |
| 4 | `aws secretsmanager put-secret-value` for the webhook | open | `terraform show \| grep hooks.slack` returns anything |
| 5 | Trigger one benign event; confirm invocation, Slack alert, `DRY_RUN` audit item with a full snapshot, **and that the resource is unchanged** | open | The resource changed. Dry-run means dry-run |
| 7 | Detonate with `dry_run` still true | open | — |
| 8 | `dry_run = false`, **lab only**, re-detonate, `make timing` | open | — |
| 9 | Deliberately trip the circuit breaker and watch it hold | open | It doesn't. A control never observed working is a comment |
| 10 | Consider dev/prod — with `dry_run = true` for a week of real traffic first | open | The false-positive rate is unknown |

**Do not go past step 5 into step 8 without doing step 6.** Turning on
remediation while the patterns are unconfirmed means a system that might not
fire, or might fire on the wrong resource, holding write access to AWS.

### Two safety notes worth repeating out of the table

**`make attack` detonates real attack techniques against a real AWS account.**
It prints the resolved account ID and requires typed confirmation.
`attack-sim/assert.sh` and `measure.sh` additionally refuse to start unless
`STRATUS_LAB_ACCOUNT_ID` is exported *and* equals the resolved caller identity —
a stale SSO session pointed at the wrong account is the realistic failure mode.
Isolated lab account only.

**Stratus leaves resources behind.** Run `stratus status` after every session.
A forgotten `t3.micro` in `sa-east-1` is ~USD 9/month, against a USD 20/month
ceiling shared with AwLZ. That is the realistic way to blow the budget — not
this stack, which costs ~USD 2.35/month at rest.

---

## 5. Where things live

```
detections/<id>/            pattern.json + metadata.yaml (ATT&CK, provenance, gaps)
remediations/common/        the pipeline — this is where the invariants are enforced
remediations/<pkg>/         handler.py + policy.json + README.md, one per detection
notifier/                   Slack payload, dedup, redaction
infra/                      root stack; infra/modules/detection is the unit of isolation
tests/support/eventbridge.py  local pattern evaluator — a reimplementation (ADR-010)
tests/fixtures/             15 fixtures, every one carrying a _pac_fixture marker
attack-sim/                 scenarios.yaml, assert.sh, measure.sh — written, never run
scripts/                    build-lambda.sh, check-detection-coverage.sh
docs/evidence/              empty, and that is correct
```

### The one design decision to understand before changing anything

The pipeline order is the security property, so it lives in exactly one place
and handlers never see it:

```
plan (read-only)  →  exclusion tag  →  SNAPSHOT TO AUDIT TABLE  →
circuit breaker   →  dry-run gate   →  apply  →  audit close  →  alert
```

A handler implements `plan()` and `apply()` and nothing else. It never calls the
audit log, the breaker, or the notifier — so it cannot snapshot late, cannot
skip the breaker, and cannot act during a dry run. Adding a detection means
adding those two methods, not wiring a pipeline.

Two conventions inside that: `plan()` returning `None` is the normal benign case
and must never be treated as an error; a plan with **no** `intended_actions`
means "this is real and a human has to do it" and produces an `ESCALATED`
outcome.

### Reading order for the other docs

1. [PAChandbook.md](PAChandbook.md) — how things get built here: build order,
   the ten-gate validation loop, the defects that loop actually caught, and the
   end-to-end checklist for adding a detection.
2. [session-report.md](session-report.md) — §3 (fixtures to capture) and §4
   (apply order). The operational handoff.
3. [architecture.md](architecture.md) — 15 ADRs. Read before disagreeing with a
   design choice; the reasoning is probably already there.
3. [threat-model.md](threat-model.md) — R1–R10 with implementation status, plus
   the static-analysis suppression register.
4. [mitre-attack.md](mitre-attack.md) — coverage *and* the deliberate gaps.
5. `remediations/<pkg>/README.md` — per-detection decision, remediation,
   rollback, and known gaps.
6. [../AGENTS.md](../AGENTS.md) — conventions and the decisions not to
   relitigate.

---

## 6. Known gaps, with what closes each

Nothing here is a surprise waiting to be discovered; it is all recorded in the
threat model and the MITRE mapping too.

| Gap | Severity | What closes it |
|---|---|---|
| **Fixtures unverified** | Highest | Capture real events (session-report §3). Until then threat R4 is instrumented, not mitigated |
| **No dead-man's-switch heartbeat** (R3) | High | A scheduled canary event through each rule plus an alarm with `treat_missing_data = "breaching"`. The existing alarms catch a *failing* detection; a *deleted* rule emits no metric at all, so nothing fires |
| **No T1098 detection** | High | Backdoor IAM users and extra access keys are the most common persistence step after initial compromise. Largest coverage gap |
| `ModifySecurityGroupRules` not covered | Medium | Its own rule and fixtures. It can widen a rule to `0.0.0.0/0` without emitting `AuthorizeSecurityGroupIngress`, so `sg-open` has a documented blind spot |
| Live CI job commented out | Medium | Enabling it means giving Actions credentials that can detonate techniques. Do it after watching a manual run, not before |
| IPv6-only and prefix-list ingress | Low | Noted in `detections/sg-open/metadata.yaml` |
| No egress detection | Low | Deliberate — revoking egress breaks more than it protects |
| Demo GIF | Low | Nothing to record yet |

### One thing that deserves a second opinion

`s3-public` treats a wildcard-principal policy carrying **any** `Condition` as
not public. That is deliberately conservative and is the right default — a
policy scoped by `aws:PrincipalOrgID` or a VPC endpoint is the normal way to
share a bucket, and remediating it is threat R2 with our own false positive
playing the attacker. But a policy conditioned on something toothless
(`aws:SecureTransport`, say) slips through. Tightening it means enumerating
which conditions actually restrict, which is real work with its own false
positives. Worth revisiting once there is traffic to measure against.
See `_policy_is_public` in `remediations/s3_public/handler.py`.

---

## 7. Running the gates on this machine

Windows 11, PowerShell 7. **Nothing is on `PATH` in a fresh shell** and there
are no shims in `WinGet\Links`.

| Tool | Location |
|---|---|
| `ruff`, `mypy`, `pytest`, `checkov` | `C:\Users\Pedro\AppData\Local\Python\pythoncore-3.14-64\Scripts` — or `python -m ruff`, `python -m checkov.main`, which always work |
| `terraform`, `tflint`, `trivy`, `shellcheck` | `C:\Users\Pedro\AppData\Local\Microsoft\WinGet\Packages\<Vendor>.<Tool>_*\` |

Other traps, all learned the hard way in this session:

- PowerShell `&&` short-circuits — a chained gate stops at the first failure and
  the rest silently never run. Check each separately or read the whole output.
- `terraform -chdir=$var` does not expand the variable in PowerShell. Use a
  literal.
- The PowerShell tool's working directory **persists between calls**. A second
  `Set-Location infra` fails because you are already there. Use absolute paths.
- The Bash tool has a narrower `PATH` than PowerShell. Use PowerShell for tools,
  Bash for `.sh` scripts.
- Local Python is 3.14; CI and the Lambda runtime are **3.13**. The code targets
  3.13.
- Makefiles assume a POSIX shell — Git Bash or WSL.

Installed: terraform 1.15.8, tflint 0.64.0 (+aws ruleset 0.44.0), trivy 0.72.0,
checkov 3.3.8, shellcheck, aws-cli 2.36.9, Python 3.14.

AWS auth is IAM Identity Center SSO, profile `mgmt`, region `sa-east-1`.
Sessions expire after an hour. **Never introduce a static access key.**

---

## 8. Cost

~**USD 2.35/month** at rest, against a USD 20/month ceiling shared with AwLZ.

77% of that is three flat charges that cost the same whether the system sees one
event or ten thousand: one KMS CMK (USD 1.00), nine CloudWatch alarms
(USD 0.90), one Secrets Manager secret (USD 0.40). Lambda, EventBridge,
DynamoDB on-demand, SQS, and X-Ray are effectively free at this volume.

Full breakdown, including what an event storm would actually cost and why the
Stratus instances are the real budget risk, in
[session-report.md](session-report.md) §5.

---

## 9. Conventions a new contributor will trip over

- Detection ID is kebab (`s3-public`) everywhere — alerts, IAM, Terraform,
  directories. The Python package is the snake form (`s3_public`). Mechanical,
  recorded in `metadata.yaml`, enforced by the coverage script.
- CI **fails on a pattern test with no `assert not matches`.** A pattern tested
  only for what it catches passes forever while quietly matching everything.
- Fixtures prefixed `benign-` must **not** match the pattern. Anything else must
  match — the handler may still decide to do nothing, which is a separate,
  separately tested claim.
- Promoting a fixture to `verified` requires updating both the fixture marker and
  the detection's `metadata.yaml`, or `tests/test_fixture_provenance.py` fails.
- No runtime dependencies. Everything the handlers use is the standard library or
  the Lambda runtime's own boto3. A deployment package with no vendored wheels
  has no supply chain to review before each deploy.
- No live AWS in unit tests, ever. `moto` only.
- Every scanner suppression carries an inline justification *and* a row in the
  threat model's suppression register. There are six; three are false positives
  (checkov applying identity-policy rules to a KMS *key* policy) and three are
  accepted risks with a stated closing condition.
- `make build` must run before `terraform plan` or `apply` — `archive_file`
  needs the staged package to exist.
- Commits: Conventional Commits, author `heavensnipe@gmail.com`. Note the local
  git config email differs; pass `-c user.email=` or fix the config.
