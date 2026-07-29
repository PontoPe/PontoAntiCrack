# `s3-public`

> **Fixtures in `tests/fixtures/cloudtrail/s3-public/` are derived from AWS
> documentation, not from an observed event.** They have not been confirmed
> against a real CloudTrail record from this organisation. See
> [docs/session-report.md](../../docs/session-report.md) for how to capture the
> real ones.

## Signal

| | |
|---|---|
| Source | CloudTrail via EventBridge |
| Pattern | [`detections/s3-public/pattern.json`](../../detections/s3-public/pattern.json) |
| Events | `PutBucketAcl`, `PutBucketPolicy`, `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock` |
| ATT&CK | [T1530](https://attack.mitre.org/techniques/T1530/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |
| Severity | high |

The pattern is coarse on purpose. Whether a bucket ended up public is not
decidable from the API call — `PutBucketPolicy` with a policy that grants
`Principal: "*"` and `PutBucketPolicy` that tightens an existing policy are the
same event name. So the pattern catches all four mutating APIs and the handler
reads the bucket back to decide.

Failed calls are excluded (`errorCode` absent). An `AccessDenied` on
`PutBucketAcl` is an attacker being stopped by IAM, which is worth logging and
is not worth waking a Lambda for.

## Decision

The handler treats a bucket as exposed when either is true:

- an ACL grant targets `AllUsers` or `AuthenticatedUsers`
- a bucket policy statement is `Allow`, has a wildcard principal, **and carries
  no `Condition`**

The condition exclusion is deliberate and errs toward inaction. A policy that is
public *and* conditioned is rare; a policy that is safe *because* of its
condition — `aws:PrincipalOrgID`, a VPC endpoint, an IP allow-list — is
everywhere. Auto-remediating those is threat R2 (remediation as DoS) with the
attacker replaced by our own false positive.

If public grants exist but all four Block Public Access settings are already on,
the handler returns no plan: the exposure is already neutralised and changing
anything would be noise.

## Remediation

1. `PutPublicAccessBlock` with all four settings `true`.
2. `PutBucketAcl` with `ACL=private`, only if the ACL is what went public.

**The bucket policy is never deleted.** Block Public Access already blocks a
public policy from taking effect, so deleting it buys nothing — and it destroys
both the operator's intent and the record of what the attacker granted
themselves. Reversal is one `DeletePublicAccessBlock` away, and the prior ACL
and policy are in the audit table verbatim.

## Execution role

[`policy.json`](policy.json). Read the six `GetBucket*` calls the decision needs,
write only `PutBucketAcl` and `PutBucketPublicAccessBlock`, both constrained by
`aws:ResourceAccount` so the role is useless cross-account.

The explicit `Deny` matters more than the `Allow`: this role cannot read an
object, delete a bucket, write a bucket policy, or turn off versioning or
logging. An attacker who reaches it gets the ability to make buckets *more*
private and nothing else.

`Resource` on the allow statements is `arn:aws:s3:::*` because the bucket that
will need remediating is not knowable at deploy time. The account condition plus
the deny statement are what bound it.

## Rollback

```
aws s3api delete-public-access-block --bucket <name>
aws s3api put-bucket-acl --bucket <name> --access-control-policy file://<snapshot>.json
```

The snapshot is the `snapshot` attribute of the audit item with
`pk = AUDIT#s3-public#<bucket>`.

## Known gaps

- Access Points and Multi-Region Access Points can expose a bucket without any
  of the four watched APIs firing. Not covered.
- A public *object* ACL inside a private bucket is not covered; `IgnorePublicAcls`
  from the remediation does neutralise it going forward.
