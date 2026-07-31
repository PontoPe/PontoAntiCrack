# Pattern gate — EventBridge agrees with every fixture

Produced by `make patterns` (`scripts/verify-patterns.sh`) on
**2026-07-30T16:24-03:00**, from the `awlz-lab` account in `sa-east-1`.

This is the check ADR-010 promises. The unit tests evaluate patterns with a
local reimplementation of the EventBridge pattern language so they need no AWS
account; that is a convenience and not an authority. The service is the only
evaluator whose opinion decides whether a detection fires in production.

Expectation comes from the fixture filename: `benign-*` must **not** match,
everything else must. The `_pac_fixture` provenance marker is stripped before
the event is sent, so the service evaluates exactly the document CloudTrail or
GuardDuty would deliver.

```text
  ok    iam-key-leak   benign-ec2-instance-finding                    false
  ok    iam-key-leak   benign-low-severity-recon                      false
  ok    iam-key-leak   credential-exfiltration-assumed-role           true
  ok    iam-key-leak   unauthorized-access-malicious-ip-caller        true
  ok    iam-key-leak   unauthorized-access-root-credentials           true
  ok    s3-public      benign-get-bucket-acl                          false
  ok    s3-public      benign-put-bucket-acl-access-denied            false
  ok    s3-public      delete-public-access-block                     true
  ok    s3-public      put-bucket-acl-public-read                     true
  ok    s3-public      put-bucket-policy-wildcard-principal           true
  ok    sg-open        authorize-ingress-https-world                  true
  ok    sg-open        authorize-ingress-rdp-world-ipv6               true
  ok    sg-open        authorize-ingress-ssh-world                    true
  ok    sg-open        benign-authorize-ingress-failed                false
  ok    sg-open        benign-authorize-ingress-internal-cidr         false

15 fixtures, 0 disagreements with the service
```

## What this settles

**Assumption 1 — EventBridge accepts `$or` where `sg-open` uses it.** It does.
Three `sg-open` positives and two negatives all evaluated, so the pattern is
syntactically accepted and semantically discriminating. Had `$or` been rejected
in that position the call would have failed outright rather than returning a
verdict, and `create-rule` would have failed at apply.

**Assumption 2 — the `ipPermissions.items[].ipRanges.items[].cidrIp` nesting.**
The pattern depends on that exact encoding, and it discriminates correctly:
`0.0.0.0/0` matches, an internal CIDR does not. A wrong assumption here would
have shown up as `sg-open` matching nothing while every unit test passed.

**No local/service disagreement.** The ADR-010 reimplementation and the service
returned the same verdict on all fifteen documents. That is the specific risk
the local evaluator carries, and it is measured rather than assumed.

## What this run did not settle, and what did

At the time of this run the fixtures were still written from documentation, so
it proved the patterns agreed with the service **about those documents** — not
that the documents matched what CloudTrail emits. The event-name assumption in
particular could not be settled by a fixture that asserts the very name in
question.

B3 answered that by capturing real events; see `fixture-capture.md`. The gate
was re-run against the captured fixtures, and again after `sg-open` grew the
legacy-encoding branch, and reports **seventeen agreements, zero
disagreements**. That later run is the one that carries the claim.

One limit survives both runs. A gate can only compare a pattern against the
documents it is given. `sg-open` was blind to an entire CloudTrail encoding of
`AuthorizeSecurityGroupIngress` while this gate was green, because no fixture
carried that encoding — the AWS CLI had produced them all. Only detonating the
technique surfaced it (`detonation-sg-open.md`). A pattern gate proves the
pattern means what its author intended; it cannot prove the author knew every
shape the service emits.
