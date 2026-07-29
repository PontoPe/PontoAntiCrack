# `sg-open`

> **Fixtures in `tests/fixtures/cloudtrail/sg-open/` are derived from AWS
> documentation, not from an observed event.** The nested
> `requestParameters.ipPermissions.items[].ipRanges.items[].cidrIp` shape and the
> `$or` block in the pattern are the two things most likely to be wrong, and both
> are load-bearing. See [docs/session-report.md](../../docs/session-report.md).

## Signal

| | |
|---|---|
| Source | CloudTrail via EventBridge |
| Pattern | [`detections/sg-open/pattern.json`](../../detections/sg-open/pattern.json) |
| Events | `AuthorizeSecurityGroupIngress` |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/), [T1021](https://attack.mitre.org/techniques/T1021/) |
| Severity | high |

The pattern filters on the CIDR inside the request, so an ingress rule from
`10.0.0.0/8` never reaches the Lambda. `$or` covers IPv4 `0.0.0.0/0` and IPv6
`::/0` in one rule.

Port filtering is *not* in the pattern. Ranges (`FromPort`/`ToPort`) cannot be
evaluated by an EventBridge pattern, so a rule opening 443 to the world matches
and is then deliberately left alone by the handler. This is the intended split:
the pattern is cheap and coarse, the handler is precise.

## Decision

A permission entry is remediated when it has a world-open CIDR **and** its port
range covers at least one port in `SENSITIVE_PORTS` — remote administration,
databases, and datastores that historically ship without authentication.
`IpProtocol: "-1"` covers everything and always qualifies.

80 and 443 alone do not qualify. A public web server is the normal reason a
security group exists.

## Remediation

`RevokeSecurityGroupIngress` with a **narrowed** permission entry: same protocol
and port range, but only the world-open CIDRs.

A rule that allows both `10.0.0.0/8` and `0.0.0.0/0` on port 22 keeps the first
and loses the second. Revoking the whole permission entry would take down
legitimate internal access — that is exactly the shape of threat R2, an outage
caused by our own remediation rather than by the attacker.

The complete prior `IpPermissions` list is written to the audit table in the
exact structure `AuthorizeSecurityGroupIngress` accepts, so restoring is a copy
of that field back into the API.

## Execution role

[`policy.json`](policy.json).

`ec2:Describe*` is granted on `Resource: "*"` because **EC2 `Describe` actions do
not support resource-level permissions** — this is an AWS API limitation, not a
scoping shortcut. The write, `ec2:RevokeSecurityGroupIngress`, is scoped to
security groups in this account and region.

The `Deny` blocks every action that could *widen* access: no `Authorize*`, no
`CreateSecurityGroup`, no `DeleteSecurityGroup`, no `RunInstances`, no
`ModifyNetworkInterfaceAttribute`. The role can close ports. That is all it can
do.

## Rollback

```
aws ec2 authorize-security-group-ingress --group-id <sg> --ip-permissions file://<snapshot>.json
```

Take `snapshot.ip_permissions_revoked` from the audit item with
`pk = AUDIT#sg-open#<group-id>`.

## Known gaps

- `ModifySecurityGroupRules` can widen an existing rule to `0.0.0.0/0` without
  emitting `AuthorizeSecurityGroupIngress`. Its `requestParameters` shape differs
  enough to need its own rule and its own fixtures. Not written.
- A rule sourced from a managed prefix list that itself contains `0.0.0.0/0` is
  not matched.
- Egress is out of scope.
