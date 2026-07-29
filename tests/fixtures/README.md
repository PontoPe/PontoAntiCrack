# Fixtures

**Every fixture in this tree is derived from AWS documentation. None has been
confirmed against an event this organisation actually produced.**

That is a legitimate starting point and a real limitation, and it is marked in
three places so it cannot quietly stop being true:

1. a `_pac_fixture` object inside every fixture file
2. `fixture_verified_against_live_event: false` in each
   `detections/*/metadata.yaml`
3. `tests/test_fixture_provenance.py`, which fails if a fixture is missing the
   marker or if a fixture claims to be verified while its detection metadata
   still says otherwise

The claim this repository makes is "detections are tested against recorded
CloudTrail events". Until the `_pac_fixture` markers say `"verified"`, the
honest version is "tested against the documented event schema". The capture
procedure for each one is in
[docs/session-report.md](../../docs/session-report.md).

## Marker

```json
"_pac_fixture": {
  "status": "derived-from-documentation",
  "verified_against_live_event": false,
  "source": "<where the shape came from>",
  "capture": "<the command that would produce the real one>"
}
```

`_pac_fixture` is an extra top-level key. EventBridge ignores event fields a
pattern does not mention, so its presence cannot change a match result.

To promote a fixture: capture the real event, diff it against the fixture, keep
the real one, set `"status": "verified"` and
`"verified_against_live_event": true`, and flip
`fixture_verified_against_live_event` in the detection metadata.
