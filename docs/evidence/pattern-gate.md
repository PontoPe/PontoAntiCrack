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

## What this does not settle

The fixtures are still derived from documentation — each one says so in its own
`_pac_fixture.verified_against_live_event: false`. This run proves the patterns
agree with the service **about these documents**. It does not prove the
documents match what CloudTrail actually emits.

That is a different question and it is what B3 answered by capturing real
events — see `fixture-capture.md`. The gate was re-run against the captured
fixtures and still reports fifteen agreements, which is the run that carries
the claim. The event-name assumption in particular — that CloudTrail emits
`DeleteBucketPublicAccessBlock` rather than the API's `DeletePublicAccessBlock`
— cannot be settled here, because the fixture asserts the very name under
question. Re-run this gate after the fixtures are replaced; the run that
matters is the one against captured events.
