# `iam-key-leak`

> **Fixtures in `tests/fixtures/guardduty/iam-key-leak/` are derived from AWS
> documentation, not from an observed finding.** No GuardDuty finding from this
> organisation has been captured yet. See
> [docs/session-report.md](../../docs/session-report.md).

## Signal

| | |
|---|---|
| Source | GuardDuty findings via EventBridge |
| Pattern | [`detections/iam-key-leak/pattern.json`](../../detections/iam-key-leak/pattern.json) |
| Finding types | `UnauthorizedAccess:IAMUser/*`, `CredentialAccess:IAMUser/*`, `Impact:IAMUser/*`, `PenTest:IAMUser/*` |
| ATT&CK | [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) |
| Severity | critical |

GuardDuty makes the anomaly call. This detection does not attempt to re-derive
"key used from an unexpected ASN" from raw CloudTrail — GuardDuty already has
the threat intelligence and the baseline, and a home-grown reimplementation
would be worse at it while costing more.

The pattern requires `severity >= 4` (MEDIUM and above) and
`resource.resourceType == "AccessKey"`. A LOW-severity finding, or a finding
about an EC2 instance, does not reach the Lambda.

## Decision

Two paths:

**Root or unidentified principal → escalate, never act.** A `userType` of `Root`,
or a finding with no `userName`, produces a plan with *no intended actions*. The
runtime turns that into an `ESCALATED` outcome: the snapshot is written, a
critical alert fires, and nothing is changed.

This is not caution for its own sake. An automation role that can disable root
credentials is a larger problem than the finding it is responding to, and a
false positive against root locks the account owner out of their own account.
The blast radius of being wrong is worse than the blast radius of waiting for a
human.

**IAM user key → deactivate.** Unless the key is already `Inactive`, in which
case there is nothing to do and re-issuing the call would put a misleading
`APPLIED` record in the audit table.

## Remediation

`UpdateAccessKey` with `Status=Inactive`.

**The key is never deleted.** `GetAccessKeyLastUsed` — which service the key
touched, in which region, when — disappears with the key, and in a
credential-abuse investigation that is frequently the only evidence of what the
attacker actually reached. It is captured into the snapshot *before* the
deactivation, and the deactivation itself is a one-line undo.

This is not a convention that depends on the handler remembering it:
`iam:DeleteAccessKey` is explicitly denied in the execution role.

## Execution role

[`policy.json`](policy.json). Four read actions and exactly one write
(`iam:UpdateAccessKey`), all scoped to
`arn:aws:iam::<account>:user/*` — the role cannot touch a role, a policy, or the
account root.

The `Deny` is the interesting half. It blocks `CreateAccessKey`,
`CreateLoginProfile`, `AttachUserPolicy`, `PutUserPolicy`, `PassRole`,
`AssumeRole`, `CreatePolicyVersion`, `SetDefaultPolicyVersion` — the standard IAM
privilege-escalation primitives. A Lambda role holding IAM write permissions is
threat R1 in its purest form, and the deny list is what makes this one a dead end
rather than a ladder.

## Rollback

```
aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Active
```

Do that only after the key is known good. The audit item
(`pk = AUDIT#iam-key-leak#<AKIA...>`) holds the prior status, the creation date,
and the full last-used record.

## Known gaps

- Keys belonging to the root account are escalated, never remediated. By design.
- A leaked key with no GuardDuty coverage (GuardDuty disabled in that account, or
  the abuse not matching a finding type) is not detected. The org-wide GuardDuty
  enablement in [AwLZ](../../../AwLZ) is the control for that.
- Temporary credentials from an assumed role are not access keys and cannot be
  deactivated; revoking those means attaching a deny-by-date policy to the role,
  which is a different remediation and is not written.
