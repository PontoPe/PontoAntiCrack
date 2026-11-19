# Dedicated SG canary — deployment and incident runbook

Status: implemented and tested offline, **not deployed or validated on AWS**.
This is a real EC2 ingress authorization, not a synthetic EventBridge heartbeat.
It temporarily permits public IPv4 SSH on an **unattached disposable SG**.
Never enable it on a workload firewall, in management/production, or without a
reviewed plan, existing state and tested independent notification delivery.

## Deployment boundary

The `sg-open` deployment is deliberately fail-closed: its entrypoint is now
`remediations.sg_open.scope.lambda_handler`. Even when `canary_enabled=false`,
its Terraform lifecycle precondition requires explicit lab account/region,
`sg_scope_group_id` and `canary_round`. The previous account-wide revoke policy
is replaced by an exact-group/tag allow. **This is a breaking migration**, not
an opt-in-only infrastructure addition. Do not apply to the historical stack
without reviewing the role, handler and scope changes together.

The unguarded `SgOpen` class remains for unit tests. Deployment uses the guarded
class. It checks STS account, client/event region, event account, exact group,
group owner, `pac-` name, `pac:canary=<round>`, absence of `pac:exclude` (even an
empty value), and absence of ENIs. Apply rechecks eligibility. IAM constrains
both producer authorize and remediator revoke to the same exact SG/tag, with no
CreateTags grant. Tags are not account isolation, and ENI attachment can race
inspection; the dedicated no-workload boundary remains essential.

Official permission reference (checked 2026-11-17):
[AWS EC2 service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html).
Both `AuthorizeSecurityGroupIngress` and `RevokeSecurityGroupIngress` list
`security-group` and `ec2:ResourceTag/${TagKey}` support. This documentation check
is not proof of deployed IAM behavior; a live allowed/denied test is still due.

## Identity, inventory and plan gates

1. Use only the approved lab session through the official AWS CLI. Check STS
   and account alias; a profile **name** is not identity. Region is `sa-east-1`.
   Compare against the privately confirmed lab allowlist. A management session
   named `awlz-lab` has been observed on this host: stop on that mismatch.
2. Locate the existing PAC backend and state using approved configuration.
   Do not recreate the AwLZ organization, trail, shared logs bucket or state
   backend. Never print state, tfvars, tokens or webhook values into evidence.
3. Inventory the existing VPC, PAC resources, table/key/topic, rules and SGs.
   Confirm the budget: incremental ceiling USD 10 for this round. Obtain a
   regional estimate and a bounded observation/cleanup window before apply.
4. Stage with `PATH="$PWD/.venv/bin:$PATH" make build`. Set `dry_run=true`.
   For automatic canary creation, opt in with `canary_enabled=true`, an explicit
   existing `canary_vpc_id`, unique `canary_round`, and tested `alarm_topic_arn`.
   The SG is newly created with no standing ingress/egress. No VPC/instance is
   created by the canary. Review the entire plan; no destructive or shared
   infrastructure changes are accepted just to make the demo run.
5. Both schedules start **DISABLED**. Review deployment and test independent SNS
   delivery before enabling the exact producer/observer rules. Do not disable
   or replace organizational logging or another round's rules.

## Protocol and interpretation

```text
UTC minutes 0/5  producer -> snapshot/conditional slot claim -> EC2 authorize
                          -> CloudTrail -> existing sg-open EventBridge rule
                          -> scoped remediation -> audit close + verified revoke
UTC minutes 4/5  separate observer -> ledger + audit query + safe SG read
                                  -> PAC/Canary EffectVerified (0 or 1)
                                  -> CloudWatch alarm -> independent SNS topic
```

Producer uses the scheduled timestamp, not retry arrival time, for the slot.
Events older than 60 seconds, future, missing or malformed are rejected before
clients are created. A conditional claim prevents a second authorization within
a slot. A failure after the claim never retries authorization or overwrites the
snapshot. A still-open group prevents another probe. Lambda async retries and
EventBridge target retries are disabled; maximum event age is 60 seconds.

Observer runs only in the first 30 seconds of minute 4 and has a 30-second
Lambda timeout, so its current-state inspection completes before the next
probe. A late run fails; missing data is unhealthy. It judges the **current**
five-minute slot, not an older completed slot against a newly opened probe.
Normal delivery must finish by this observation window; slower delivery is an
unhealthy result, not silently treated as success. These bounds are protocol
choices, **not measured delivery latency guarantees**.

A `1` requires a producer `ISSUED` claim, the same CloudTrail `requestID`, exact
account/region/SG, a non-dry-run `APPLIED` audit within this slot, the exact
`revoked ingress tcp/22-22 from 0.0.0.0/0 from <group>` action, and a safe current
SG. A different revoke, empty actions, missing evidence, `PLANNED`/`FAILED`
correlated attempt, or outside-window completion cannot pass. The exact-action
check is deliberately conservative: unexpected combined rule shapes may alarm
rather than be attributed to this probe. No claim of exactly-once processing or
serializability is made.

Alarm: minimum over 300 seconds, two of two periods below 1, missing data
`breaching`, both ALARM and OK notifications. Measure actual alarm/resolve and
notification times; CloudWatch ingestion/evaluation adds delay. Observer has no
EC2/audit mutation or remediation invoke permission. It is independent of the
rule/Lambda under test, but shares account, EC2, DynamoDB, KMS, EventBridge and
CloudWatch: it does **not** survive a total account/control-plane outage.

## Live acceptance — must still be executed

Preserve sanitized raw output, times, resource ownership and commit SHA for:

- EventBridge pattern positives and benign negatives; do not equate moto with
  service pattern evaluation.
- Dry-run: snapshot present, `DRY_RUN`, SG byte-equivalent before/after.
  Producer authorization is still a real mutation; explicitly clean only that
  probe after recording evidence and before enabling the next run.
- Live IPv4/IPv6 correction preserving private SSH and public HTTPS. Canary
  itself emits IPv4 only; IPv6 is a separate guarded manual acceptance case.
- Replay, two actual concurrent deliveries and a delayed already-safe event;
  inspect every audit item, final SG and attributed actions.
- Breaker and denied out-of-scope/excluded resources. Do not attach the SG to an
  instance to test attachment refusal; that refusal is covered offline.
- Snapshot failure prevents mutation; audit-close interruption leaves unresolved
  `PLANNED` and cannot be hidden by a later successful replay.
- Independently test SNS delivery. Interrupt **only** the dedicated `sg-open`
  path under test; preserve observer and producer schedules. Observe `0` and
  actual ALARM delivery. Restore the exact saved rule/target/function setting,
  safely reconcile any stale probe, and observe new correlated `1` and OK
  delivery. Do not restore unsafe ingress from a snapshot.

## Failure, reconciliation and cleanup

1. Stop the exact producer schedule first; preserve observer/alarms and evidence.
2. Treat `PLANNED` as unknown, not unchanged. Correlate ledger, audit deliveries,
   request ID and current SG. Never relabel an unresolved delivery automatically.
3. Record human reconciliation separately. After reviewed scoped cleanup of a
   stuck probe, a new slot can test the restored path; this does not retroactively
   resolve an older ambiguous audit record.
4. Disable the exact round's schedules after the experiment. Remove only its
   newly created SG, functions/roles/log groups/queues/rules/alarm through a
   separately reviewed cleanup plan. Retain audit evidence and shared PAC/AwLZ
   resources. Do not run stack-wide `terraform destroy`.
5. Re-inventory to prove no attachments/residues and that shared logging is
   unchanged. Record actual usage/cost or billing-delay limitations. No current
   live cleanup proof or cost measurement exists for this increment.

## Offline reproduction

With the manifest-backed Python 3.13 venv and static tools installed:

```sh
export PATH="$PWD/.tools/bin:$PWD/.venv/bin:$PATH"
unset PYTHONPATH
pytest tests/ -q
ruff check .
ruff format --check .
mypy remediations/ notifier/ canary/
make build coverage
shellcheck -x -S warning scripts/*.sh attack-sim/*.sh .githooks/pre-commit
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra init -backend=false -input=false
terraform -chdir=infra validate
tflint --chdir=infra --recursive
```

Run Trivy/Checkov against source-only infra copies (no state/tfvars), with
updates/telemetry/downloads/uploads disabled as recorded in the evidence. This
is not a Terraform plan. Enable the fail-closed local secret hook with
`git config core.hooksPath .githooks`; install Gitleaks 8.30.1 first. CI verifies
the official release checksum before running the secret scan. No PR credentials
or live AWS deployment capabilities were added.
