# Session report — 2026-07-29

> Orientation and current state live in [handoff.md](handoff.md). This document
> is the operational detail behind it: what to capture, in what order to apply,
> and what it costs.

Written in one autonomous session with no AWS access. Everything below was
validated locally: `pytest`, `ruff`, `ruff format`, `mypy --strict`,
`terraform fmt`, `terraform validate`, `tflint`, `trivy config`, `checkov`,
`shellcheck`. No AWS API call was made, including `sts get-caller-identity`.

**Nothing has been applied. `terraform plan` has never been run** — it needs
credentials. The `apply` is yours.

---

## 1. What is ready to apply

| Area | State |
|---|---|
| `infra/` | Terraform for three detections: EventBridge rule, Lambda, one execution role each, DynamoDB audit table, one KMS CMK, Secrets Manager secret, per-detection SQS dead-letter queue, nine CloudWatch alarms. `validate` clean, `tflint` clean, `trivy config` zero findings, `checkov` zero failures with six justified skips. |
| `detections/` | Three EventBridge patterns plus ATT&CK/provenance metadata. |
| `remediations/` | Three handlers, three scoped IAM policies, three READMEs, and the shared pipeline that enforces snapshot-before-change, tag exclusion, circuit breaker, and dry-run. |
| `notifier/` | Slack payload builder with blast-radius context, conditional-write deduplication, credential redaction. |
| `tests/` | 167 tests. Per detection: the pattern matches, the pattern does *not* match the plausible-but-benign case, and the handler takes the right action. Plus pipeline invariants, redaction, config, and tests for the pattern evaluator itself. |
| `attack-sim/` | Three Stratus scenarios, `assert.sh`, `measure.sh`. Written, executable, **not run**. |
| `scripts/` | `build-lambda.sh` (stages the deployment package), `check-detection-coverage.sh` (CI gate). |
| `docs/` | 15 ADRs, updated threat model with a suppression register, MITRE mapping including deliberate gaps. |
| `docs/evidence/` | **Empty, correctly.** Nothing has been measured. |

Verification output at the end of the session:

```
167 passed
ruff: All checks passed!
mypy: Success: no issues found in 22 source files
terraform validate: Success! The configuration is valid.
tflint: (no issues)
trivy config infra: 0 misconfigurations
checkov -d infra: Passed 76, Failed 0, Skipped 6
scripts/check-detection-coverage.sh: all detections complete
```

---

## 2. Decisions made on your behalf

Full reasoning in [architecture.md](architecture.md); this is the summary of the
ones that could reasonably have gone the other way.

| # | Decision | Why | How to undo |
|---|---|---|---|
| ADR-002 | Patterns are **coarse**; the handler reads the resource back and decides | A pattern cannot evaluate a port range or parse a policy. Encoding everything in the pattern buys false negatives, which are the expensive kind | Narrow the pattern; the handler no-op path stays correct either way |
| ADR-005 | **One deployment artifact**, three handler entrypoints | Avoids vendoring `common` and `notifier` three times and keeping the copies in step. Isolation comes from IAM, not the artifact boundary | Split `build-lambda.sh` per package |
| ADR-009 | Root and **temporary** credentials are escalated, never acted on | An automation role that can disable root is a bigger problem than the finding. `UpdateAccessKey` cannot touch a session credential at all — pretending otherwise would report a confident `APPLIED` for a remediation that never happened | Nothing to undo; a new remediation would be needed |
| — | `s3-public` treats a **conditioned** wildcard policy as safe | `Principal: "*"` scoped by `aws:PrincipalOrgID` or a VPC endpoint is the normal way to share a bucket inside an org. Remediating it is threat R2 with our own false positive as the attacker | `_policy_is_public` in `remediations/s3_public/handler.py` |
| — | `s3-public` **never deletes the bucket policy** | Block Public Access already neutralises a public policy. Deleting it destroys both the operator's intent and the record of what the attacker granted themselves | It would be a new action in `apply()` |
| — | `sg-open` revokes **only the world-open CIDRs**, keeping the rest of the entry | A rule allowing both `10.0.0.0/8` and `0.0.0.0/0` on 22 must keep the first. Revoking the whole entry is an outage we caused | `_world_open_dangerous_part` |
| — | `sg-open` leaves 80/443 alone | A public web server is a design choice | `SENSITIVE_PORTS` |
| ADR-012 | **One KMS CMK** for the table, secret, queues, and log groups | USD 1/month each against a USD 20/month total budget, for components that share a failure domain anyway | Split into four keys, +USD 3/month |
| ADR-015 | Lambdas **not in a VPC** | NAT gateway is USD 32/month, more than the whole budget, to protect against a path the function never takes | Add `vpc_config`, remove the checkov skip |
| ADR-008 | Circuit breaker counts **dry-run attempts too** | A dry-run deployment that would have tripped the breaker is exactly the signal you want before enabling remediation | `check_and_increment` call site in `runtime.py` |
| ADR-010 | Local **reimplementation** of the EventBridge pattern language in tests | The authoritative evaluator is an AWS API call, and you said no AWS calls | Replace with `aws events test-event-pattern` in a live job |
| ADR-013 | Fixture provenance is **machine-checked** | Presenting unverified fixtures as verified kills the thesis. A marker nobody checks stops being true within a month | `tests/test_fixture_provenance.py` |
| — | GuardDuty severity floor of **4 (MEDIUM)** for `iam-key-leak` | Deactivating a production key because GuardDuty saw routine enumeration is threat R2 | `detections/iam-key-leak/pattern.json` |
| — | Detections deployed **per account**, not centrally with cross-account assume | A remediation role that can leave its own account is a much better target (R1) | Add provider aliases in `infra/providers.tf` |

---

## 3. Every fixture that needs confirming against a real event

**This is the most important section in this document.** The repository's claim
is "detections are tested against recorded CloudTrail events". Today it is
"tested against the documented event schema". Every item below is what closes
that gap.

Each fixture carries a `_pac_fixture` marker with its own `capture` command.
`tests/test_fixture_provenance.py` fails if a marker goes missing or contradicts
its detection's `metadata.yaml`, so this cannot quietly be forgotten.

### The general procedure

The cheapest capture path, once applied, is the detection's own log group — the
handler receives the delivered event, and `PAC_LOG_LEVEL=INFO` puts the outcome
in the log. To get the *event* itself, temporarily set `PAC_LOG_LEVEL=DEBUG` and
add a `log.debug("%s", json.dumps(raw_event))` at the top of
`entrypoint.lambda_handler` — or read it from the org trail:

```bash
aws s3 cp "s3://<org-trail-bucket>/AWSLogs/<org-id>/<lab-account>/CloudTrail/sa-east-1/2026/07/29/" . \
  --recursive --profile log-archive
gunzip -c *.json.gz | jq '.Records[] | select(.eventName == "AuthorizeSecurityGroupIngress")'
```

A trail record is *not* the same shape as the EventBridge envelope — the trail
record becomes the `detail` object, and EventBridge wraps it with
`version`/`id`/`detail-type`/`source`/`account`/`time`/`region`/`resources`. The
wrapper is stable and documented; the `detail` is what needs confirming.

Then, for each pattern, confirm the pattern itself against the real service:

```bash
aws events test-event-pattern \
  --event-pattern file://detections/sg-open/pattern.json \
  --event "$(jq -c . tests/fixtures/cloudtrail/sg-open/authorize-ingress-ssh-world.json)"
```

This is the check that closes ADR-010's limitation. Run it for all fifteen
fixtures — positives must return `true`, `benign-*` must return `false`.

### `s3-public` — 5 fixtures

| Fixture | Must | How to capture |
|---|---|---|
| `put-bucket-acl-public-read.json` | match | `aws s3api put-bucket-acl --bucket <lab-bucket> --acl public-read` |
| `put-bucket-policy-wildcard-principal.json` | match | `aws s3api put-bucket-policy --bucket <lab-bucket> --policy file://public.json` |
| `delete-public-access-block.json` | match | `aws s3api delete-public-access-block --bucket <lab-bucket>` |
| `benign-get-bucket-acl.json` | **not** match | `aws s3api get-bucket-acl --bucket <lab-bucket>` |
| `benign-put-bucket-acl-access-denied.json` | **not** match | Call `PutBucketAcl` with a principal lacking `s3:PutBucketAcl` |

**Highest-risk assumption:** that CloudTrail names the event
`DeleteBucketPublicAccessBlock` and not `DeletePublicAccessBlock` (the API name).
If it is the latter, that detection path is dead and the pattern needs both.

**Second:** how CloudTrail renders the policy document in
`requestParameters.bucketPolicy`. The fixture has it as a nested object; it may
arrive as a JSON *string*. This does not affect the pattern (which does not read
it) but does affect anyone reading the audit snapshot.

### `sg-open` — 5 fixtures

| Fixture | Must | How to capture |
|---|---|---|
| `authorize-ingress-ssh-world.json` | match | `aws ec2 authorize-security-group-ingress --group-id <sg> --protocol tcp --port 22 --cidr 0.0.0.0/0` |
| `authorize-ingress-rdp-world-ipv6.json` | match | `... --ip-permissions 'IpProtocol=tcp,FromPort=3389,ToPort=3389,Ipv6Ranges=[{CidrIpv6=::/0}]'` |
| `authorize-ingress-https-world.json` | match (handler then ignores) | `... --protocol tcp --port 443 --cidr 0.0.0.0/0` |
| `benign-authorize-ingress-internal-cidr.json` | **not** match | `... --protocol tcp --port 22 --cidr 10.0.0.0/8` |
| `benign-authorize-ingress-failed.json` | **not** match | Call it with a principal lacking `ec2:AuthorizeSecurityGroupIngress` |

**Highest-risk assumptions, both load-bearing:**

1. The nested list encoding
   `requestParameters.ipPermissions.items[].ipRanges.items[].cidrIp`. If EC2
   renders it flat, the pattern matches nothing.
2. That EventBridge accepts `$or` in the position used here. `$or` is
   documented at the top level of a pattern, which is where it is placed, but
   this has not been confirmed against the service. If it is rejected, split
   into two rules (IPv4 and IPv6) targeting the same function.

`test-event-pattern` answers both in one call, and it is the very first thing to
run after apply.

### `iam-key-leak` — 5 fixtures

| Fixture | Must | How to capture |
|---|---|---|
| `unauthorized-access-malicious-ip-caller.json` | match, then remediate | `aws guardduty create-sample-findings --detector-id <id> --finding-types UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` |
| `unauthorized-access-root-credentials.json` | match, then **escalate** | Do not reproduce with real root credentials. Take a sample finding and edit `userType`/`userName` to `Root` |
| `credential-exfiltration-assumed-role.json` | match, then **escalate** | Stratus `aws.credential-access.ec2-steal-instance-credentials` |
| `benign-low-severity-recon.json` | **not** match | `create-sample-findings --finding-types Discovery:IAMUser/AnomalousBehavior` |
| `benign-ec2-instance-finding.json` | **not** match | `create-sample-findings --finding-types CryptoCurrency:EC2/BitcoinTool.B!DNS` — high severity, but `resourceType` is `Instance`, so there is no key to deactivate |

**Caveat on sample findings:** `create-sample-findings` produces synthetic
`resource` values. The envelope and the `type`/`severity`/`resourceType` fields
the pattern reads are real; `accessKeyDetails` is not. Good enough to confirm the
pattern, not good enough to confirm the handler's field access. A real finding is
needed for that, and it will take as long as it takes.

### Promoting a fixture

1. Replace the file contents with the captured event, keeping `_pac_fixture`.
2. Set `"status": "verified"` and `"verified_against_live_event": true`.
3. When **all** of a detection's fixtures are verified, flip
   `fixture_verified_against_live_event: true` in
   `detections/<id>/metadata.yaml`.
4. `make test`. Flipping one without the other fails, on purpose.
5. Update the "Detonated" column in the README table only after detonation, not
   after capture. They are different claims.

---

## 4. Apply order and what to verify after each step

Do not skip a step because the previous one looked fine. Steps 3 and 6 are where
this either works or does not, and step 8 is the one that is tempting to rush.

### 0. Prerequisites

- [AwLZ](../../AwLZ) applied through `modules/logging`: org trail delivering,
  GuardDuty enabled in the lab account.
- `aws sso login --profile mgmt`, then a profile for the lab account.
- Lab account ID to hand.

### 1. Build the deployment package

```bash
make build
```

Verify: `build/lambda/` holds `remediations/` and `notifier/`, no `__pycache__`,
no `.md`, no `policy.json`.

### 2. Configure and plan

```bash
cp infra/example.tfvars infra/terraform.tfvars   # gitignored
# set account_id, environment = "lab", leave dry_run = true
terraform -chdir=infra init -backend-config=backend.hcl
terraform -chdir=infra plan
```

Verify in the plan output, before applying:

- exactly 3 IAM roles, named `pac-<id>-remediation`. **If there is one shared
  role, stop** — something is wrong with the module wiring, and that is threat R1.
- `PAC_DRY_RUN = "true"` in all three functions' environments.
- No `secret_string` on `aws_secretsmanager_secret`. Terraform must never hold
  the webhook.
- `deletion_protection_enabled = true` on the table.

### 3. Apply

```bash
terraform -chdir=infra apply
```

Then, immediately, the check that matters most:

```bash
for d in s3-public sg-open iam-key-leak; do
  echo "== $d"
  aws events test-event-pattern \
    --event-pattern file://detections/$d/pattern.json \
    --event "$(jq -c . tests/fixtures/*/$d/<a-positive-fixture>.json)"
done
```

**A `false` here means the detection is dead on arrival**, regardless of how many
unit tests pass. This is ADR-010's limitation being closed. If `$or` in
`sg-open` is rejected, the `create-rule` call in step 3 will itself have failed —
that is the loud version of the same problem.

### 4. Populate the webhook

```bash
aws secretsmanager put-secret-value \
  --secret-id pac/slack-webhook \
  --secret-string '{"webhook_url":"https://hooks.slack.com/services/..."}' \
  --profile lab
```

Verify: `terraform -chdir=infra show | grep -i hooks.slack` returns nothing.

### 5. Trigger one benign event, in dry-run

```bash
aws ec2 authorize-security-group-ingress \
  --group-id <a-throwaway-lab-sg> --protocol tcp --port 22 --cidr 0.0.0.0/0 --profile lab
```

Verify, in order:

1. `aws logs tail /aws/lambda/pac-sg-open --since 5m` — the function was invoked.
2. A Slack message arrives, marked `[lab] sg-open — would remediate (dry run)`,
   naming the principal, the source IP, and the interface count.
3. `aws dynamodb query --table-name pac-audit --key-condition-expression 'pk = :pk' --expression-attribute-values '{":pk":{"S":"AUDIT#sg-open#<sg-id>"}}'`
   — one item, `status = DRY_RUN`, `snapshot` holding the full prior
   `ip_permissions_before`.
4. **The rule is still there.** `describe-security-groups` still shows
   `0.0.0.0/0` on 22. Dry-run means dry-run; if the rule is gone, stop and find
   out why before going any further.
5. `aws sqs get-queue-attributes --queue-url <pac-sg-open-dlq> --attribute-names ApproximateNumberOfMessages`
   — zero.

### 6. Capture the real event and fix the fixtures

Section 3 above. Then `make test` locally and push. **Do not proceed to step 8
until this is done** — turning on remediation while the patterns are unconfirmed
means a system that might not fire, or might fire on the wrong thing, with write
access to production.

### 7. Detonate, still in dry-run

```bash
export STRATUS_LAB_ACCOUNT_ID=<lab-account>
make attack TTP=aws.defense-evasion.security-group-open-port-22-ingress
```

`assert.sh` will report a `DRY_RUN` record where it expects `APPLIED` and fail.
That is correct and expected at this stage — read the audit item by hand and
confirm the *plan* was right.

### 8. Turn off dry-run — lab only

```hcl
dry_run = false
```

Re-apply, re-detonate, and this time `assert.sh` should pass. Then:

```bash
make timing   # writes docs/evidence/time-to-remediate.md
```

That file is the first real evidence this repository will contain.

### 9. Exercise the circuit breaker deliberately

Open and re-open the same security group six times inside five minutes with
`circuit_breaker_max_actions = 5`. Expect four `APPLIED` then `BLOCKED` with a
critical alert. A control that has never been observed working is a comment.

### 10. Only then consider dev or prod

And only with `dry_run = true` for at least a week of real traffic first, with
the `SKIPPED`/`DRY_RUN` audit records reviewed for false positives. The
false-positive rate on real traffic is the only number that says whether this is
safe to let act.

---

## 5. Cost

Monthly, `sa-east-1`, at the volume this will actually see (a handful of events
a day). Your ceiling is USD 20/month, shared with AwLZ.

| Service | What | Cost |
|---|---|---|
| KMS | 1 customer-managed key | **USD 1.00** |
| CloudWatch | 9 alarms (3 detections × errors, throttles, dead-letters) | **USD 0.90** |
| Secrets Manager | 1 secret | **USD 0.40** |
| CloudWatch Logs | ingest + storage, ~10 MB/month at 365-day retention | ~USD 0.02 |
| DynamoDB | on-demand, PITR, <1 MB of data | ~USD 0.01 |
| Lambda | arm64, 256 MB, ~1s per invocation, low hundreds of invocations | ~USD 0.00 (free tier) |
| EventBridge | rules matching AWS service events | USD 0.00 (not billed) |
| SQS | dead-letter queues, normally empty | ~USD 0.00 (free tier) |
| X-Ray | active tracing | ~USD 0.00 (100k traces free) |
| **Total** | | **≈ USD 2.35/month** |

Notes on the shape of that number:

- **77% of it is three flat charges** — the CMK, the alarms, and the secret.
  They cost the same whether the system sees one event or ten thousand.
- **The alarms are the easiest cut.** Dropping the `throttles` alarm saves
  USD 0.30/month and loses the earliest signal that the concurrency cap is being
  hit. Not worth it; noted in case the budget tightens.
- **What could actually surprise you:** an event storm. Lambda and DynamoDB are
  per-request, and the circuit breaker limits *remediations*, not *invocations*.
  A million-event storm is roughly USD 0.20 of Lambda and USD 1.25 of DynamoDB
  writes — annoying, not dangerous, and the reserved concurrency of 5 caps the
  rate. Set an AWS Budgets alert anyway.
- **Not included:** Stratus Red Team detonations create real EC2 instances. An
  un-cleaned `t3.micro` in `sa-east-1` is about USD 9/month. `make attack` runs
  `stratus cleanup`; check `stratus status` after every session regardless. This
  is the realistic way to blow the budget.
- **Not included:** the org trail, GuardDuty, Config, and Security Hub, which
  belong to AwLZ's side of the ceiling.

---

## 6. Where I was less than certain, and what is half-done

Being straight about this, since you asked.

### Unverified assumptions that are load-bearing

Listed in section 3 and in `docs/architecture.md` under "Open questions". The
three that would each break a whole detection:

1. `$or` placement in `detections/sg-open/pattern.json`.
2. The `items[]` nesting in EC2's CloudTrail `requestParameters`.
3. `DeleteBucketPublicAccessBlock` vs `DeletePublicAccessBlock` as the event name.

All three are answered by one `test-event-pattern` call each, in step 3.

### The pattern evaluator is mine, not AWS's

`tests/support/eventbridge.py` implements the subset of the pattern language in
use. It raises rather than guessing on anything else, and has its own tests. But
a green detection test means "the pattern says what I meant", not "EventBridge
agrees". Stated in ADR-010, in the module docstring, and in the README.

### Genuinely incomplete

| Thing | State |
|---|---|
| Dead-man's-switch heartbeat (threat R3) | **Not built.** The alarms catch a *failing* detection; a *deleted* rule emits no metric at all, so nothing fires. Needs a scheduled canary event through each rule plus a `treat_missing_data = "breaching"` alarm. This is the biggest gap in the threat model, and I left it rather than shipping a half-canary. |
| `ModifySecurityGroupRules` | **Not built.** It can widen an existing rule to `0.0.0.0/0` without emitting `AuthorizeSecurityGroupIngress`, so `sg-open` has a documented blind spot. Different `requestParameters` shape; needs its own rule and fixtures, and writing them from documentation would have added a fourth unverified guess. |
| T1098 Account Manipulation | **No detection.** Backdoor IAM users and extra access keys are the most common persistence step after an initial compromise. Largest coverage gap; noted in `docs/mitre-attack.md`. |
| Live CI job | Scaffolded and **commented out**. Enabling it means giving GitHub Actions credentials that can detonate attack techniques, which should happen after you have watched a manual run, not before. |
| Demo GIF | Nothing to record. |
| `docs/evidence/` | Empty, and correctly so. |

### Things I chose not to do

- **No `terraform plan`.** It needs credentials. `validate` passes, which catches
  syntax and type errors but not, for example, an IAM policy AWS will reject at
  `PutRolePolicy`. Expect the first `apply` to surface something.
- **No suppression of a real finding without a written reason.** Six checkov
  skips total: three are false positives (checkov applying identity-policy rules
  to a KMS *key* policy) and three are accepted risks with an owner and a closing
  condition, all registered in the threat model.
- **No widening of an execution role to make a test pass.** The one place it was
  tempting — `ec2:Describe*` on `Resource: "*"` — is an AWS API limitation
  (EC2 Describe actions have no resource-level permissions), stated as such
  rather than glossed over.

### One thing worth a second opinion

`s3-public` treats a wildcard-principal policy **with any `Condition`** as not
public. That is deliberately conservative and it is the right default — but a
policy conditioned on something toothless (`aws:SecureTransport`, say) would slip
through. Tightening it means enumerating which conditions actually restrict,
which is a real piece of work and a source of its own false positives. Worth
revisiting once there is real traffic to measure against.
