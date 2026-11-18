# Verifying response, not invocation

## Question

Can an AWS response pipeline remain safe under duplicate, concurrent and
interrupted deliveries—and detect that its own response path has disappeared?

This extends PontoAntiCrack's existing CloudTrail → EventBridge → Lambda
`sg-open` response, rather than adding more detections. Inspiration:
[Jonathan Rau, AWS — Automated Response and Remediation with AWS Security Hub](https://aws.amazon.com/blogs/security/automated-response-and-remediation-with-aws-security-hub/).
The article motivates event-driven response; PAC uses direct CloudTrail events
and deliberately narrower, lab-only permissions. Historical runtimes/IAM from
the article are not copied as current deployment guidance.

## What changed

The earlier handler could overwrite a delivery's forensic snapshot, report a
competing successful removal as a failure, or trust a successful API response
without checking the effect. Local regressions demonstrated these failures.
Each delivery now retains its own audit record; apply intersects the snapshot
with current state, verifies the target is absent and never expands an old
plan. Neither a snapshot nor a replay authorizes reopening unsafe ingress.

The new canary opens TCP/22 to IPv4-world on one explicitly scoped, unattached
SG. An independently scheduled read-only observer requires the same API request
ID, a completed non-dry-run audit with the exact revoke action, and the safe
post-condition. A Lambda invocation by itself is not success. The observer
also rejects unresolved correlated attempts. It cannot establish serializability
across DynamoDB and EC2 or survive loss of the shared AWS account/control plane.

Independent review found two additional observer defects before publication:
accepting an unrelated revoke as the canary effect, and assessing an old probe
against a newer probe's temporarily open SG. Exact-target checks and disjoint
producer/observer windows now have executable regression tests.

## Evidence and limits

[Replay evidence](evidence/reliability-v2.md),
[canary evidence](evidence/canary-offline.md), and
[runbook](runbooks/canary.md) separate tool outputs from interpretation.
All new execution evidence is offline (moto, synthetic deliveries and injected
failures). No new AWS detonation, notification delivery, alarm/resolve latency,
cleanup proof or incremental cost measurement is claimed. The 5.97-second July
measurement belongs to the historical deployment, not this increment.

The host's profile name suggested a lab session, but STS identified management.
Deployment stopped at that boundary. The remaining live proof requires the
approved lab session, existing backend/state, reviewed plan, independent SNS
delivery test and bounded cost/cleanup window. The changed SG entrypoint/IAM is
an intentional breaking, fail-closed migration and must not be blindly applied
to the historical stack.

## Reproduction and result still to collect

Follow the offline commands and then the separately gated live matrix in the
runbook. Record a real event's path to state correction; interrupt only the
sandbox rule; measure observer alarm delivery and subsequent recovery; remove
only this round's resources. Until that experiment runs, this is a tested
implementation—not proof of current AWS availability.

## CV bullet (accurate for the offline increment)

Built and regression-tested a fail-closed AWS response canary with request-ID
correlation, per-delivery forensic snapshots, resource-scoped IAM and independent
effect verification; reproduced replay/concurrency/failure defects without
claiming exactly-once processing or unmeasured live reliability.

## Question for the article author (draft; not sent)

For event-driven response systems, which independently observed post-conditions
have you found most useful for distinguishing successful invocation from actual
remediation—especially when a response partially succeeds but the audit close
fails?
