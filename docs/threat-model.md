# Threat model — Ponto Anti-Crack

## Scope

The detection and response pipeline itself: CloudTrail / GuardDuty → EventBridge
→ Lambda → notification, plus the IAM that lets it act. Two directions matter
here — threats it detects, and threats *against it*. The second is the one
people forget.

**Status:** the controls below are implemented and unit-tested. None has been
validated by detonation. Where a control's effectiveness depends on an
assumption about AWS event shapes, that assumption is currently unconfirmed —
see R4 and [session-report.md](session-report.md).

## Assets

| Asset | Why it matters |
|-------|----------------|
| Remediation Lambda execution roles | They hold write permissions on production resources — an escalation target |
| EventBridge rules | Deleting one silently blinds a whole detection |
| Audit table (DynamoDB) | The record of what was auto-changed and what it looked like before; also the rollback source |
| Slack webhook | Leaked = alert spoofing and information disclosure |
| CloudTrail | The input to everything |

## Trust boundaries

1. AWS control plane → EventBridge (event delivery; events are data, and are
   parsed defensively — a missing key is an unknown value, never an exception)
2. Lambda → target resources (crossed by scoped IAM)
3. Lambda → Slack (crossed by an outbound webhook carrying account context)
4. Attack simulation tooling → lab account (must never cross into a real account)

## Threats against the response system

| # | Threat | Likelihood | Impact | Control | Status | Residual risk |
|---|--------|-----------|--------|---------|--------|---------------|
| R1 | Remediation role over-privileged → used as an escalation path | Med | High | One role per detection, scoped to exact actions, plus explicit `Deny` on the escalation primitives (`iam:PassRole`, `sts:AssumeRole`, `iam:AttachUserPolicy`, `ec2:Authorize*`, `s3:GetObject`…). `sts:AssumeRole` trust policy conditioned on `aws:SourceAccount` and `aws:SourceArn`. | implemented | Needs review each time a remediation grows. `ec2:Describe*` is `Resource: "*"` because EC2 Describe actions do not support resource-level permissions — an AWS limitation, not a shortcut. |
| R2 | Attacker weaponizes auto-remediation as DoS (mass-revoking prod SGs) | Med | High | Dry-run default (ADR-007); `pac:exclude` tag exclusion; per-detection circuit breaker in DynamoDB **plus** Lambda reserved concurrency (ADR-008); surgical revokes that keep non-world CIDRs; conservative publicness test that treats a conditioned wildcard policy as safe. | implemented | A determined attacker can still generate noise and trip the breaker, which blinds that detection until a human clears it. That trade is deliberate: blind-and-loud beats destructive-and-automatic. |
| R3 | Detection path disabled (rule deleted, Lambda unwired) | Med | High | SCP protects `pac-*` resources (from [AwLZ](../../AwLZ)); DynamoDB `deletion_protection_enabled` and `prevent_destroy`; alarms on function errors, throttles, and dead-letter depth. | partial | **No dead-man's-switch heartbeat yet.** A rule that is deleted rather than failing produces no metric at all, so the error alarm never fires. This is the largest open gap in the model. |
| R4 | Event schema drift → detection stops matching, silently | High | High | Fixture-based unit tests in CI; coverage guard that also requires a negative assertion; dead-letter alarm. | **weakened** | **Every fixture is currently derived from documentation, not from an observed event.** So the tests prove internal consistency, not agreement with AWS. Until the fixtures are captured (see session-report.md), R4 is not meaningfully mitigated — it is only instrumented. `tests/test_fixture_provenance.py` makes this state impossible to forget. |
| R5 | Slack webhook leaked | Low | Med | Secret in Secrets Manager under the stack CMK, referenced by ARN; never in an environment variable, `.tfvars`, or state; `redact.scrub` strips webhook URLs and credential-named keys from every payload and every audit record. | implemented | **No automatic rotation** (accepted, see suppressions below). Slack webhooks have no rotation API; rotating means creating a new one by hand. |
| R6 | Remediation destroys evidence needed for IR | Med | High | Snapshot written to the audit table before any mutation (ADR-003); audit records have no TTL; role denied `dynamodb:DeleteItem`; bucket policies neutralised rather than deleted; access keys deactivated rather than deleted, enforced by an IAM `Deny` on `iam:DeleteAccessKey`. | implemented | Key deactivation is semi-destructive by design — deliberate, and reversible with one CLI call. |
| R7 | Alert fatigue → real finding ignored | High | Med | Conditional-write deduplication with an exact window (ADR-014); status is part of the dedup fingerprint so a later escalation is not swallowed; alerts carry principal, source IP, resource, blast radius; benign outcomes do not alert at all. | implemented | Tuning is ongoing. The `SKIPPED`-with-exclusion-tag case *does* alert, on purpose — an excluded resource going public is a decision worth seeing. |
| R8 | Attack simulation detonated in a real account | Low | High | `make attack` prints and confirms the account ID; `assert.sh` and `measure.sh` refuse unless `STRATUS_LAB_ACCOUNT_ID` is set **and** equals the resolved caller identity; live CI job gated on a manual-approval environment and disabled. | implemented | Human error at the confirm prompt is the last line. |
| R9 | Remediation re-triggers its own detection (invocation loop) | Med | Med | The runtime drops events whose principal ARN contains the `pac-` prefix, before planning. Tested. | implemented | Depends on the role naming convention holding. A remediation role renamed away from `pac-*` would reopen this. |
| R10 | Under-scoped execution role makes a detection report everything as safe | Med | High | `s3-public` only swallows the specific "not configured" error codes; `AccessDenied` propagates and surfaces as a `FAILED` outcome with a critical alert. Tested. | implemented | Only `s3-public` reads configuration that may legitimately be absent; the other two have no equivalent path. |

## Threats it detects

| ID | Technique | ATT&CK | Signal | Response |
|----|-----------|--------|--------|----------|
| `s3-public` | Public bucket exposure | T1530, T1562.001 | CloudTrail `PutBucketAcl` / `PutBucketPolicy` / `PutBucketPublicAccessBlock` / `DeleteBucketPublicAccessBlock`, then the bucket is read back | Enable all four Block Public Access settings; reset a public ACL; retain the policy as evidence |
| `iam-key-leak` | Stolen access key used | T1552.001, T1078.004 | GuardDuty `UnauthorizedAccess:IAMUser/*`, `CredentialAccess:IAMUser/*`, `Impact:IAMUser/*`, `PenTest:IAMUser/*` at severity ≥ 4 on an `AccessKey` resource | Capture `last-used`, set the key Inactive. Root and temporary credentials escalate instead |
| `sg-open` | Management port open to the world | T1190, T1021 | `AuthorizeSecurityGroupIngress` with `0.0.0.0/0` or `::/0` | Revoke only the world-open CIDRs on permission entries covering a sensitive port |

Full mapping, including what is deliberately *not* covered:
[mitre-attack.md](mitre-attack.md).

## Static analysis suppressions

Every suppression carries its justification inline at the point of suppression.
They are listed here so the set can be reviewed as a whole, which is the only
way to notice it growing.

| Check | Where | Real finding? | Justification |
|---|---|---|---|
| `CKV_AWS_109`, `CKV_AWS_111`, `CKV_AWS_356` | `infra/kms.tf`, `data.aws_iam_policy_document.kms` | No — false positive | checkov applies identity-policy rules to a **KMS key policy**. In a key policy `Resource: "*"` is self-referential and is the only form AWS accepts. The `kms:*` grant to the account root is mandatory; without it the key becomes unmanageable. |
| `CKV2_AWS_57` | `infra/secrets.tf` | **Yes — accepted** | Slack incoming webhooks have no rotation API. Automating a rotation that cannot be automated would mean a rotation Lambda holding write access to this secret — more attack surface for no gain. Accepted residual under **R5**; closed by moving to a Slack app with a rotatable token. |
| `CKV_AWS_117` | `infra/modules/detection/main.tf`, Lambda not in a VPC | **Yes — accepted** | The functions reach only public AWS endpoints and the Slack webhook. A VPC needs a NAT gateway (~USD 32/mo) or five interface endpoints (~USD 36/mo), against a USD 20/mo total budget, to protect against lateral movement into a VPC the function never touches. See ADR-015. Closed if a remediation ever needs a private resource. |
| `CKV_AWS_272` | `infra/modules/detection/main.tf`, no code signing | **Yes — accepted** | Signed artefacts require the build to hold a Signer identity, putting a new credential into a CI pipeline that currently holds none. Worse trade than the risk removed while this is single-author and built from a pinned commit. Closed when CI gains deploy credentials. |

Nothing else is suppressed. `trivy config` reports zero findings without any
suppression; checkov reports zero with the six above.

## Validation

A detection is not done until: unit tests pass on a fixture **captured from a
real event**, and the technique has been detonated in the lab account with the
alert and the remediation asserted, and time-to-remediate recorded in
`docs/evidence/`.

By that standard, **no detection in this repository is done.** All three pass
unit tests against documentation-derived fixtures. `docs/evidence/` is empty and
stays empty until something is actually measured.

## Assumptions

- The org trail is delivering to the security account ([AwLZ](../../AwLZ)) and
  GuardDuty is enabled org-wide.
- The lab account is isolated, budget-capped, and contains no real data.
- Detections are deployed per account, not centrally with cross-account assume —
  a remediation role that can leave its own account is a far better target.
