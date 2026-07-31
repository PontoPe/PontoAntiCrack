# Handbook — how this repository gets built

Method, not state. This is the procedure for building and extending
PontoAntiCrack, written from the session that produced it, including the parts
that went wrong.

| Document | Answers |
|---|---|
| **PAChandbook.md** (this file) | *How* things get built here, and what the process catches |
| [PAChandoff.md](PAChandoff.md) | Where the project stands right now |
| [session-report.md](session-report.md) | What to capture, what to apply, in what order, at what cost |
| [architecture.md](architecture.md) | *Why* each design decision went the way it did (ADR-001…015) |
| [threat-model.md](threat-model.md) | What we are defending against, and what is still open |

---

## 1. The organising idea

Every part of this repository exists to make one claim survivable:

> The detection is code, it has tests, and it was proven by attacking the
> account.

Three words in that sentence do all the work — *tests*, *proven*, *account*. So
the process is built to make it impossible to accidentally overstate any of
them:

- **tests** — a detection cannot merge without a test that asserts what it
  matches **and** one that asserts what it does not
  (`scripts/check-detection-coverage.sh`)
- **proven** — a fixture that has not been confirmed against a real event says
  so, in the file, in the metadata, and in a test that fails if the two
  disagree (`tests/test_fixture_provenance.py`)
- **account** — anything that touches a real account requires a typed
  confirmation and an account-ID match (`make attack`, `attack-sim/assert.sh`)

If you are adding something and you cannot see which of those three it
protects, that is worth a second look before writing it.

---

## 2. Build order, and why it is that order

The session built the repository in this sequence. It is not arbitrary, and
repeating it for a new component saves rework.

| # | Step | Why here |
|---|---|---|
| 1 | Read the scaffold, the sibling repo's conventions, and check the toolchain | Conventions are cheaper to match than to retrofit. Finding out `ruff` is not installed after writing 2,000 lines is worse than finding out first |
| 2 | Project config (`pyproject.toml`, `requirements-dev.txt`) and kick off `pip install` in the background | The install runs while you write. Lint rules chosen up front means code is written to them rather than reformatted into them |
| 3 | Detection patterns and metadata | They are the contract. Everything downstream — handler, policy, fixtures, tests — is shaped by what the pattern delivers |
| 4 | Shared runtime (`remediations/common/`) | Types, then the pipeline. Writing the pipeline **before** the handlers is what keeps handlers small: by the time you write one, snapshot/breaker/dry-run/alerting already exist and are not yours to think about |
| 5 | Notifier | Depends on the models from step 4, nothing else depends on it |
| 6 | The three handlers, with their policies and READMEs | Now each one is `plan()` + `apply()` and little else |
| 7 | Tests, in one pass over everything | — |
| 8 | Run the Python gates, fix what they find | See §4 |
| 9 | Terraform | Last, because it encodes the environment-variable contract and the handler module paths, and both were still moving until step 8 |
| 10 | Scripts, attack simulation | Depend on resource names that Terraform fixes |
| 11 | Docs | Written when the decisions are settled and still fresh |
| 12 | Commit in coherent slices, push | See §9 |

**The one inversion worth calling out:** the pipeline came before the handlers.
The alternative — write one handler end to end, then extract the common parts —
produces a "common" module shaped by whichever detection happened to be first.
Writing the invariants first, from the threat model, meant all three handlers
had to fit a pipeline designed for none of them in particular.

---

## 3. How a detection is built

A detection is a **unit**. Partial ones are worse than absent ones: they occupy
a row in the README, look like coverage, and match nothing. CI enforces the
whole list.

### The eight files

```
detections/<id>/pattern.json           the cheap filter
detections/<id>/metadata.yaml          ATT&CK, severity, provenance, known gaps
remediations/<pkg>/handler.py          plan() and apply(), nothing else
remediations/<pkg>/policy.json         the extra power this detection needs
remediations/<pkg>/README.md           decision, remediation, rollback, gaps
tests/fixtures/<src>/<id>/*.json       ≥2, at least one named benign-*
tests/detections/test_<pkg>_pattern.py must contain `assert not matches`
tests/remediations/test_<pkg>_handler.py
```

Plus a row in [mitre-attack.md](mitre-attack.md) — the coverage script greps for
it, so the map cannot drift away from what is deployed.

### Order to write them

1. **Pattern first, and keep it coarse.** An EventBridge pattern cannot evaluate
   a port range, parse a policy document, or read the resulting state of a
   resource. Encode in the pattern only what is *free* — event source, event
   name, `errorCode` absence, a literal CIDR, a severity floor. Everything that
   needs judgement belongs in the handler (ADR-002).

   The test for "am I over-filtering": if getting it wrong produces a **false
   negative**, it does not belong in the pattern. False negatives in a detection
   are silent; false positives are merely expensive.

2. **Fixtures next, before the handler.** Writing the positive and the benign
   fixture forces you to decide what the detection is actually for. The benign
   one is the harder and more valuable of the two — pick the thing a real
   engineer does every week that looks superficially identical:
   SSH from `10.0.0.0/8`, a read-only `GetBucketAcl`, a LOW-severity GuardDuty
   finding.

3. **`plan()`.** Read-only. Gather the snapshot while you are there — the
   snapshot is not an afterthought, it is the evidence that survives if `apply()`
   dies. Return `None` for the benign case; that is a normal outcome, not an
   error. Return a plan with **no** `intended_actions` for "this is real but a
   human must do it".

4. **`apply()`.** The only method allowed to mutate. Return a human-readable
   list of what was done — it goes into the audit record and the alert.

5. **`policy.json`.** Write the `Deny` block first. It is the more informative
   half and it is the one a reviewer should read. Ask: *if this role were
   stolen, what could it do?* The answer should be boring.

6. **README**, including the rollback command and the known gaps. A gap you
   name is a scoping decision; a gap you omit is a bug someone finds later.

7. **Tests**, then `make coverage`.

### The two invariants a handler must not violate

- It never calls the audit log, the circuit breaker, or the notifier.
  `remediations/common/runtime.py` does, in a fixed order. A handler that
  reaches for them is a handler that can get the order wrong.
- `apply()` must be able to run from the snapshot alone. `sg-open` stores
  `ip_permissions_revoked` in the exact shape the API takes back; `apply()` just
  posts it. This is what makes the audit record a genuine rollback source rather
  than a log line.

---

## 4. The validation loop

Ten gates. Run them in this order — each is cheaper than the one after it, and
each catches a class the others cannot.

| # | Gate | Catches | Cost |
|---|---|---|---|
| 1 | `ruff check` | Unused imports, shadowing, bare `except`, `S`-class security smells | ~1s |
| 2 | `ruff format --check` | Formatting drift | ~1s |
| 3 | `mypy --strict` | Type errors, unreachable code, missing returns | ~10s |
| 4 | `pytest` | Behaviour | ~11s |
| 5 | `check-detection-coverage.sh` | Structurally incomplete detections; a pattern test with no negative assertion | <1s |
| 6 | `shellcheck -S warning` | Quoting and word-splitting bugs in the scripts that touch real accounts | <1s |
| 7 | `terraform fmt -check -recursive` | Formatting | ~1s |
| 8 | `terraform validate` | Syntax, type, and reference errors — **not** anything AWS will reject at apply time | ~5s |
| 9 | `tflint --recursive` | Dead declarations, provider-specific mistakes | ~5s |
| 10 | `trivy config` + `checkov` | Security misconfiguration | ~30s |

Then, only on a real account, three more — and the order matters, because each
one can only be reached by passing the one before it:

| # | Gate | Catches | Needs |
|---|---|---|---|
| 11 | `terraform plan` / apply | Anything AWS rejects that `validate` cannot see | credentials |
| 12 | `make patterns` | A pattern the service reads differently than the local evaluator does | credentials only — no deployed stack |
| 13 | `stratus detonate` + read the audit table | A detection that does not fire on the attack it was written for | a wired stack in an isolated lab account |

Gate 13 is the expensive one and it is the only one that has ever found a
detection that was simply blind. See §5 and §7.

### On this machine

Nothing is on `PATH` in a fresh PowerShell. **PowerShell `&&` short-circuits**,
so a chained gate stops at the first failure and the rest silently never run —
run them separately or read the whole output.

```powershell
$env:PATH = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\Scripts;" +
            "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe;" +
            "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\TerraformLinters.tflint_Microsoft.Winget.Source_8wekyb3d8bbwe;" +
            "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe;" +
            $env:PATH
```

`python -m ruff`, `python -m mypy`, `python -m pytest`, `python -m checkov.main`
always work regardless. The `.sh` scripts and the Makefile need Git Bash or WSL.
The Bash tool has a narrower `PATH` than PowerShell — use PowerShell for tools,
Bash for scripts.

Full trap list in [PAChandoff.md](PAChandoff.md) §7.

---

## 5. What the loop actually caught

The useful part of a handbook is not the checklist, it is the evidence the
checklist works. These are the real defects found while building this, and by
which gate. None of them were hypothetical.

### Found by reasoning, before any gate ran

**Deduplication was going to over-suppress for up to 48 hours.** The first
version of `notifier/dedup.py` used a DynamoDB TTL attribute as the alert
window. DynamoDB deletes expired items *on its own schedule* — typically within
48 hours, not within the 15 minutes the window claims. A duplicate-suppression
mechanism that suppresses for a day is an outage in the alerting path, and no
unit test would have caught it because `moto` would have behaved as intended.
Fixed with a conditional write, `attribute_not_exists(pk) OR expires_at < :now`,
which also buys atomicity between concurrent invocations. Recorded as ADR-014
and tested by `test_deduplication_window_expires`.

**A broad `except` would have made an under-scoped role report every bucket as
safe.** `s3-public` has to tolerate `NoSuchBucketPolicy` and
`NoSuchPublicAccessBlockConfiguration` — a bucket with no policy is a normal,
important state. The obvious implementation is `try/except Exception: return
default`, and it is badly wrong: it swallows `AccessDenied` too, so a role
missing `s3:GetBucketAcl` would conclude "not public" for every bucket in the
account and report success forever. Fixed by allowlisting the specific
absent-configuration error codes and letting everything else propagate into a
`FAILED` outcome with a critical alert. This became threat **R10** and
`test_access_denied_while_inspecting_is_not_swallowed`.

**GuardDuty reports `resourceType: AccessKey` for credentials that are not
access keys.** Discovered while writing the `iam-key-leak` fixtures: the
`InstanceCredentialExfiltration` finding has `resourceType: AccessKey` and an
`accessKeyId` beginning `ASIA…`, but the principal is an assumed-role session.
`UpdateAccessKey` cannot touch a session credential at all. A handler that
believed the field name would have called `list_access_keys(UserName=<role
name>)`, failed, and — worse — could have reported a confident `APPLIED` for a
remediation that never happened. This is why `Status.ESCALATED` and the
empty-`intended_actions` convention exist, and why the same path covers root
credentials. Tested by `test_assumed_role_session_is_escalated`.

The lesson generalises: **field names in a security event are a claim, not a
contract.** Read what the value means, not what the key is called.

### Found by `pytest`

**A credential leaked into a Slack alert through dict flattening.**
`test_alert_never_carries_credential_material` failed on the first run.
Redaction was applied to the whole payload at the end of `build_payload`, but
`blast_radius` had already been flattened from `{"secretAccessKey": "wJalr…"}`
into the string `"secretAccessKey=wJalr…"`. Key-name-based redaction had nothing
left to match on, and the narrow value regex does not — deliberately — try to
guess what a secret looks like. Fixed by scrubbing the mapping *before*
flattening.

This is the single most valuable thing the test suite found, and it is worth
understanding why the test existed at all: it was written to assert a property
from the threat model (**R5**: no credential material leaves the account), not
to cover a line of code. Property-shaped tests catch this class; coverage-shaped
tests do not.

**A reason string enumerated 42 ports instead of saying "all".** With
`IpProtocol: "-1"`, `sg-open` reported *"allows ingress on 42 sensitive ports
including 20, 21, 22…"* rather than *"all ports and protocols"*. Cosmetic, but
it lands in an alert a human reads at 3am, so it counts.

### Found by `ruff` and `mypy`

Line lengths, an `if/else` that wanted a ternary, an exception class without an
`Error` suffix, and one genuine dead assignment in `audit.py` where `status` was
set twice — the first value never observable. Small things. The value is that
they are found in one second rather than in review.

### Found by `checkov`

Four failures on the first run. **Three were false positives and one was real,**
and telling them apart is the whole skill — see §6.

Real: `CKV_AWS_173`, Lambda environment variables not encrypted with a
customer-managed key. Fixed rather than suppressed, by setting `kms_key_arn` on
the function. That fix then required a second, *un-conditioned* `kms:Decrypt`
statement in the execution role, because Lambda decrypts a function's own
environment variables directly rather than through another service — the
existing `kms:ViaService` condition would have made the function fail to start.
A fix that introduces a startup failure at first invocation is not a fix, and
this one was only caught by reasoning through the call path, not by any gate.

### Found by `tflint`

An unused `aws_caller_identity` data source, left over from an earlier idea
about verifying the account at plan time. `allowed_account_ids` on the provider
already does that job. Deleted.

### Found by reading, after the gates were green

**A miscount in a document.** `session-report.md` §3 listed four `iam-key-leak`
fixtures. There are five — `benign-ec2-instance-finding.json` was missing from
the list of fixtures needing confirmation against a real event. That list is the
one artefact in the repository that must not have holes, since it is the whole
plan for making the central claim true. Found by counting files while writing
the handoff, not by any gate.

**Worth generalising:** the gates check the code. Nothing checks that a document
still describes the code. Re-derive counts from the filesystem rather than from
memory whenever you cite one.

### Found by detonating, with every gate green

Both of these survived 176 passing tests, a coverage gate, a pattern gate
agreeing with EventBridge on every fixture, and fixtures captured from real
CloudTrail. They are the reason gate 13 exists.

**A loop guard the attacker controls.** `Principal.is_pac_automation()` tested
`"pac-" in self.arn`. An assumed-role ARN is
`arn:aws:sts::<account>:assumed-role/<role>/<session>`, and the session name is
chosen by the caller on every `AssumeRole`. Stratus happened to run under
`pac-terraform`, so the detection classified the attack as its own automation
and recorded a confident `SKIPPED`. Anyone passing
`--role-session-name pac-anything` was invisible. The comparison is against the
role name now, which is fixed when the role is created.

*The general shape:* a security decision made from a field the adversary can
set. Ask of any predicate — who writes this string?

**A pattern that knew one of two encodings.** `AuthorizeSecurityGroupIngress`
is recorded two ways. The AWS CLI sends `IpPermissions` and CloudTrail nests
`ipPermissions.items[].ipRanges.items[].cidrIp`. A caller using the legacy
top-level parameters produces an empty `ipPermissions` with `ipProtocol`,
`fromPort`, `toPort` and `cidrIp` directly on `requestParameters`. Every fixture
had come from the CLI, so the pattern had only ever seen one shape. Port 22 was
opened to the internet and the rule did not match; the only thing that matched
was the technique's own Terraform warm-up creating a 443 rule.

*The general shape:* fixtures inherit the bias of whatever produced them. Two
tools calling the same API are two different sources of truth, and a corpus
built from one tool is a corpus with a blind spot you cannot see from inside it.

**What kept both from being worse.** The handler reads the security group back
instead of trusting the event, so a missed encoding was a missed detection
rather than a wrong remediation. And `dry_run = true` was the default through
every one of these runs, so the first live remediation happened only after the
pattern was fixed.

---

## 6. Working with the scanners

The rule is: **if the scanner is right, fix the code. If it is wrong, say why,
inline, at the point of suppression.** Never silence a check to make a build
green.

Decision procedure, in order:

1. **Read the finding and the resource.** Not the check ID — the actual thing it
   is pointing at.
2. **Is the check applying the right model?** This is where most false positives
   live. Three of the four checkov failures here were the same mistake: checkov
   evaluated a **KMS key policy** with **identity-policy** rules. In a key
   policy, `Resource: "*"` is self-referential — it means *this key* — and is the
   only form AWS accepts. The `kms:*` grant to the account root is mandatory;
   omit it and the key becomes unmanageable and unrecoverable. Neither is a
   permissions exposure, and "fixing" either would break the key.
3. **If it is right, fix it.** `CKV_AWS_173` was right.
4. **If it is right but you are accepting it, that is a risk decision, not a
   lint decision.** It needs: an inline justification, a row in the threat
   model's suppression register, and a stated condition that would close it.
   Three of the six suppressions here are accepted risks — no VPC, no code
   signing, no secret rotation — and each carries the number that makes it a
   trade rather than a shrug (a NAT gateway is USD 32/month against a USD
   20/month total budget) plus what would reopen the decision.

Suppression comments are long on purpose. A reader six months out needs the
reasoning without a git blame.

**Current state: `trivy config` reports zero findings with zero suppressions;
`checkov` reports 76 passed, 0 failed, 6 skipped.** If that count grows, read
the new finding before adding a seventh.

---

## 7. What the gates cannot tell you

The most important discipline in this repository is knowing where the local
evidence runs out.

**`terraform validate` is not `terraform plan`.** It checks syntax, types, and
references. It does not talk to AWS, so it cannot know whether an IAM policy
will be rejected at `PutRolePolicy`, or whether a resource name collides.
Expect the first apply to surface something.

**A green pattern test does not mean the pattern works.** `tests/support/
eventbridge.py` is a reimplementation of the EventBridge pattern language,
written because the authoritative evaluator is an AWS API call. It raises rather
than guessing on anything outside the subset it implements, and it has its own
test file — a bug there would turn every detection test green for the wrong
reason. But it proves *the pattern says what its author meant*, not *EventBridge
agrees*. Only `aws events test-event-pattern` proves the second (ADR-010).

**A fixture is a hypothesis until it is captured.** All 15 originals were
written from AWS documentation, and three assumptions inside them were
load-bearing enough that being wrong killed an entire detection. Fifteen of the
seventeen fixtures are captured events now, and the three assumptions held.

**And a captured fixture is still only one shape.** This is the limit that cost
the most to learn. `sg-open` was blind to an entire CloudTrail encoding of
`AuthorizeSecurityGroupIngress` while every gate above was green, including the
pattern gate, because every fixture had been produced by the AWS CLI and the CLI
emits only one of the two encodings. A gate compares a pattern against the
documents it is handed; it cannot tell you which documents you never thought to
hand it. Only detonating the technique did.

**`moto` is not AWS.** It is excellent for asserting that a handler calls the
right API with the right arguments and reacts correctly to the response. It does
not model IAM evaluation, eventual consistency, throttling, or the exact error
codes a real service returns under load.

The practice that follows from all of this: **state the limit next to the
claim.** Every one of the above is written in the module docstring, in the ADR,
and in the README — not only here, where someone reading the code would not
find it.

---

## 8. The honesty discipline

The repository is a portfolio artefact for a security engineering role, which
means an overstated claim is not a documentation bug — it is the failure mode
that destroys the artefact's whole purpose. Four rules, all of them mechanised
where mechanisation was possible.

1. **Separate "tested" from "proven".** The README detection table has two
   columns, `Unit tests` and `Detonated`. They were ✅ and ❌ for the whole build,
   and the distinction turned out to be the load-bearing one: `sg-open` was
   fully tested and completely blind at the same time. `sg-open` is detonated
   now; `s3-public` and `iam-key-leak` are not, and their column still says so.

2. **Provenance is machine-checked, not asserted.** Every fixture carries a
   `_pac_fixture` marker with its status and the command that would capture the
   real event. Every detection's `metadata.yaml` carries
   `fixture_verified_against_live_event`.
   `tests/test_fixture_provenance.py` fails if a marker is missing, if status
   and flag disagree, if an unverified fixture does not say how to capture the
   real one, or if a detection's metadata contradicts its fixtures. Promotion
   requires updating both places or CI fails.

   A comment saying "TODO: verify these fixtures" stops being true within a
   month and nobody notices. A test does not.

3. **Empty is a valid state, and better than plausible.** `docs/evidence/` was
   empty for the whole build because nothing had been measured, and its README
   explained what would land there and what would produce it. A table of
   realistic-looking latency numbers would have been trivial to write and would
   have made every other number in the repository worthless. It now holds four
   artefacts and exactly one latency figure — 5.97 s, one detection, one run —
   and says that is what it is.

4. **Name the gaps.** [mitre-attack.md](mitre-attack.md) has a
   *"What is deliberately not covered"* section — no T1098 detection, no
   egress, no data-destruction detection. A coverage map that only lists hits
   reads as completeness. The threat model marks R3 as **partial** and R4 as
   **weakened**, with the reason, rather than showing green everywhere.

The general form: **make the true statement cheaper to maintain than the
flattering one.**

---

## 9. Commit and review practice

**Conventional Commits**, author `heavensnipe@gmail.com`. Note the machine's
local git config uses a different address — pass
`-c user.email=heavensnipe@gmail.com` or fix the config.

**Slice by coherent change, not by file count.** This session produced eight
commits: build config, the runtime and handlers, the notifier, the tests, the
Terraform, the attack simulation, CI, docs. Each is reviewable on its own and
each subject line says what changed rather than what was touched.

**The body carries the reasoning that would otherwise be lost.** A commit
message is the only documentation that is guaranteed to stay attached to the
change. When a decision has a *why* that is not obvious from the diff — why the
bucket policy is never deleted, why the breaker counts dry runs — the body is
the right place for a sentence of it, with the long form in the ADR.

**Never commit with a gate failing.** If it is failing for a reason you have
decided to accept, that is a suppression, and §6 applies.

### Before pushing

```bash
make lint && make test && make coverage && make validate
```

From Git Bash or WSL. On PowerShell, run them separately — `&&` short-circuits.

---

## 10. Adding a fourth detection: the checklist

Concretely, end to end. Say the detection is `iam-backdoor-user` (T1098, the
current largest coverage gap).

```
 1. detections/iam-backdoor-user/pattern.json
    → coarse. CreateUser / CreateAccessKey / AttachUserPolicy, errorCode absent.
 2. detections/iam-backdoor-user/metadata.yaml
    → id, package: iam_backdoor_user, ATT&CK T1098, severity,
      fixture_status: derived-from-documentation, and the known gaps.
 3. tests/fixtures/cloudtrail/iam-backdoor-user/
    → ≥1 positive, ≥1 benign-*.json. Every file gets a _pac_fixture marker
      with a `capture` command. The benign one is the hard one: what does a
      legitimate CreateUser by the platform team look like?
 4. remediations/iam_backdoor_user/handler.py
    → plan(): read the user back, decide. None if benign; empty
      intended_actions if it must escalate.
      apply(): the minimal reversible fix.
 5. remediations/iam_backdoor_user/policy.json
    → Deny block first. What can this role do if stolen?
 6. remediations/iam_backdoor_user/README.md
    → the unverified-fixture warning at the top, signal, decision,
      remediation, execution role, rollback command, known gaps.
 7. tests/detections/test_iam_backdoor_user_pattern.py
    → must contain `assert not matches`. CI checks for the literal string.
 8. tests/remediations/test_iam_backdoor_user_handler.py
    → plan produces the right plan; plan returns None on the benign case;
      apply changes exactly what it should and nothing else;
      the snapshot is sufficient to roll back.
 9. docs/mitre-attack.md
    → a row containing `iam-backdoor-user` in backticks. The coverage script
      greps for it.
10. README.md detection table, and threat-model.md if the surface changed.
11. infra/locals.tf
    → add to local.detections; add the ID to the detections_enabled
      validation list in variables.tf.
12. make lint && make test && make coverage && make validate
13. Commit as one change. A partial detection will not pass CI, by design.
```

Steps 9–11 are the ones that get forgotten. The coverage script catches 9;
nothing catches 10 or 11 except review.

---

## 11. Reading order for someone new

1. [PAChandoff.md](PAChandoff.md) — where things stand, and what to do next
2. This file — how things get built
3. [architecture.md](architecture.md) — read before disagreeing with a design
   choice; the reasoning is probably already an ADR
4. `remediations/common/runtime.py` — one function, `execute`, and the ordering
   it enforces. The single best explanation of how the system thinks
5. `remediations/sg_open/handler.py` — the simplest complete detection
6. [threat-model.md](threat-model.md) — what all of it is defending against

If you only read two files, make them `runtime.py` and
[session-report.md](session-report.md) §3.
