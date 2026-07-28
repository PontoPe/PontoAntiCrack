# Threat model — Ponto Anti-Crack

## Scope

The detection and response pipeline itself: CloudTrail → EventBridge → Lambda → notification, plus the IAM that lets it act. Two directions matter here — threats it detects, and threats *against it*. The second is the one people forget.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Remediation Lambda execution roles | They hold write permissions on production resources — an escalation target |
| EventBridge rules | Deleting one silently blinds a whole detection |
| Audit table (DynamoDB) | The record of what was auto-changed and what it looked like before; also the rollback source |
| Slack webhook | Leaked = alert spoofing and information disclosure |
| CloudTrail | The input to everything |

## Trust boundaries

1. AWS control plane → EventBridge (event delivery; events are data, and are validated before use)
2. Lambda → target resources (crossed by scoped IAM)
3. Lambda → Slack (crossed by an outbound webhook carrying account context)
4. Attack simulation tooling → lab account (must never cross into a real account)

## Threats against the response system

| # | Threat | Likelihood | Impact | Control | Residual risk |
|---|--------|-----------|--------|---------|---------------|
| R1 | Remediation role over-privileged → used as an escalation path | Med | High | One role per detection, scoped to exact actions + resource conditions; no `iam:*`, no `PassRole` | Needs review each time a remediation grows |
| R2 | Attacker weaponizes auto-remediation as DoS (mass-revoking prod SGs) | Med | High | Dry-run mode default in non-prod, tag-based exclusion (`pac:exclude`), per-detection rate limit and circuit breaker | A determined attacker can still generate noise |
| R3 | Detection path disabled (rule deleted, Lambda unwired) | Med | High | SCP protects `pac-*` resources (from [AwLZ](../../AwLZ)); heartbeat canary event every 15 min with a dead-man's-switch alarm | — |
| R4 | Event schema drift → detection stops matching, silently | High | High | Fixture-based unit tests in CI using recorded CloudTrail events; coverage guard blocks untested detections | Fixtures age; refresh them from live captures |
| R5 | Slack webhook leaked | Low | Med | Stored in Secrets Manager, never in env vars or code; alerts carry no credential material | — |
| R6 | Remediation destroys evidence needed for IR | Med | High | Original resource state snapshotted to the audit table *before* any change; remediations are reversible | Some actions (key deactivation) are semi-destructive by design — deliberate |
| R7 | Alert fatigue → real finding ignored | High | Med | Deduplication window, severity routing, context-rich alerts (principal, source IP, resource, blast radius) | Tuning is ongoing work |
| R8 | Attack simulation detonated in a real account | Low | High | `make attack` prints and confirms the account ID; live CI job gated on a manual-approval environment | Human error — the confirm prompt is the last line |

## Threats it detects

| ID | Technique | ATT&CK | Signal | Response |
|----|-----------|--------|--------|----------|
| `s3-public` | Public bucket exposure | T1530 | CloudTrail `PutBucketAcl` / `PutBucketPolicy` granting `AllUsers`, or Config non-compliance | Remove grant, enable Block Public Access, snapshot prior policy, alert |
| `iam-key-leak` | Stolen access key used | T1552.001 | GuardDuty `UnauthorizedAccess:IAMUser/*`, key used from anomalous ASN/geo | Deactivate key (never delete), capture `last-used`, alert owner |
| `sg-open` | Management port open to the world | T1190 | `AuthorizeSecurityGroupIngress` with `0.0.0.0/0` on 22/3389/3306/etc. | Revoke rule, preserve original in audit table, alert |

## Validation

A detection is not considered done until: unit test passes on a recorded event fixture **and** the real technique has been detonated (Stratus Red Team / CloudGoat) in the lab account with the alert and remediation asserted, and time-to-remediate recorded in `docs/evidence/`.

## Assumptions

- Org trail is already delivering to the security account (AwLZ).
- The lab account is isolated, budget-capped, and contains no real data.
