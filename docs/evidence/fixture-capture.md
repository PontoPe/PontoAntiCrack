# Fixture capture — the events are real now

Captured in the `awlz-lab` account on **2026-07-30**, `sa-east-1`. Fourteen of
the fifteen fixtures are now recorded events; the fifteenth is explained below.

The claim "detections are tested against recorded CloudTrail events" was false
until this ran, and `tests/test_fixture_provenance.py` was written to keep it
from being quietly assumed. Flipping a marker without capturing the event fails
CI, and flipping the detection metadata without flipping every fixture fails it
too.

## What was executed

Each event came from a real API call in the lab, against resources created and
deleted in the same run. Total exposure was under a minute, and the CloudTrail
record is written at call time, so nothing had to be left behind.

| Detection | Positive events | Benign events |
|---|---|---|
| `s3-public` | `PutBucketAcl` public-read, `PutBucketPolicy` with a wildcard principal, `DeleteBucketPublicAccessBlock` | `GetBucketAcl`, `PutBucketAcl` refused to a principal with no S3 write permission |
| `sg-open` | ingress 22 and 443 from `0.0.0.0/0`, ingress 3389 from `::/0` | ingress 22 from `10.0.0.0/8`, ingress refused to a principal with no EC2 write permission |
| `iam-key-leak` | three GuardDuty findings by type | two GuardDuty findings by type |

The two "refused" events needed a principal that genuinely lacks the
permission. The AwLZ read-only role could not be assumed from the recovery role
— its trust policy pins the management plan role, correctly — so a throwaway
role with no policy at all was created, used and deleted in the same run.

## The highest-risk assumption survived

The handoff flagged one assumption above the others: that CloudTrail emits
`DeleteBucketPublicAccessBlock` rather than the API's own
`DeletePublicAccessBlock`. If it were the latter, that detection path was dead.

```text
lookup-events EventName=DeleteBucketPublicAccessBlock  ->  1 event
lookup-events EventName=DeletePublicAccessBlock        ->  0 events
```

The pattern was right. The other two assumptions — `$or` in the position
`sg-open` uses it, and the `ipPermissions.items[].ipRanges.items[].cidrIp`
nesting — were already settled by the pattern gate and hold against the
captured events too.

## What the real events changed

Recorded events disagreed with the hand-written ones in five places. Each was a
test encoding an assumption, and each is now the real shape:

1. **The principal is an assumed role, not an IAM user.** Every hand-written
   fixture had `arn:aws:iam::…:user/lab-operator`. Real administrative calls
   arrive as `arn:aws:sts::…:assumed-role/<role>/<session>`. Four tests asserted
   the IAM-user form.
2. **`MaliciousIPCaller` is issued against an AWS service principal.** Its
   `accessKeyDetails.userType` is `AWSService`, so the handler escalates instead
   of deactivating — a branch no hand-written fixture reached. It now has a test.
3. **`InstanceCredentialExfiltration` carries `userType: IAMUser`**, the
   opposite of what its name suggested and of what the hand-written fixture
   asserted. It is the actionable-path fixture now.
4. **`TorIPCaller` severity is 5, not 8.** The hand-written value was a guess.
5. **A real benign `GetBucketAcl` came from Access Analyzer**, not from the
   operator: the service reads a new bucket's ACL on its own. That is a better
   benign fixture than a hand-made one, because it is traffic that genuinely
   occurs and genuinely must not be remediated.

None of these were pattern defects. All five were assumptions in the tests
around the patterns, which is exactly the class of error that survives a green
suite built on documentation.

## The one fixture that is still documentation-derived

`unauthorized-access-root-credentials.json` stays
`derived-from-documentation`, and `detections/iam-key-leak/metadata.yaml`
therefore still says `fixture_verified_against_live_event: false`.

GuardDuty sample findings always carry a placeholder principal; none of them
can be issued against the account root. Capturing that event honestly would
require an actual root-credential compromise in the lab, which is not something
to manufacture. The root branch is the one where the handler refuses to act at
all, so it keeps its documentation-derived fixture and its test, and the marker
keeps saying so.

The GuardDuty fixtures that were captured are service-generated samples. Their
type, severity and resource shape are exactly what GuardDuty emits — which is
what the pattern reads — but no real compromise produced them, and each marker
says that.

## Re-verification

After replacing the fixtures, both gates were re-run against them:

```text
make test        172 passed
make patterns    15 fixtures, 0 disagreements with the service
```

That second run is the one that matters. The earlier pattern-gate run proved
the patterns agreed with the service about documents written from
documentation; this one proves they agree about events AWS actually emitted.
