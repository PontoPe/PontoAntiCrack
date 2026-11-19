# Fixtures

**Fifteen of the seventeen fixtures here are events this organisation actually
produced, captured in `awlz-lab` on 2026-07-30 and sanitized. Two are still
derived from AWS documentation, and they say so in their own markers.**

The two exceptions, and why they stayed:

- `guardduty/iam-key-leak/unauthorized-access-root-credentials.json` — GuardDuty
  sample findings always carry a placeholder principal and none can be issued
  against the account root. Capturing it honestly would mean manufacturing a
  root compromise.
- `cloudtrail/sg-open/benign-authorize-ingress-legacy-params-internal-cidr.json`
  — the legacy top-level parameter encoding, added after the detonation exposed
  it. The AWS CLI does not emit that form, so the benign counterpart could not
  be produced the way the others were.

Which fixture is which is marked in three places, so it cannot quietly stop
being true:

1. a `_pac_fixture` object inside every fixture file, per fixture
2. `fixture_verified_against_live_event` in each `detections/*/metadata.yaml`,
   `true` only when **every** fixture for that detection is verified — so
   `sg-open` and `iam-key-leak` are still `false` on the strength of one
   fixture each
3. `tests/test_fixture_provenance.py`, which fails if a fixture is missing the
   marker or if a fixture claims to be verified while its detection metadata
   still says otherwise

What changed when the fixtures stopped being guesses — including the five
assumptions real events corrected — is in
[docs/evidence/fixture-capture.md](../../docs/evidence/fixture-capture.md). The
capture procedure for each one is in
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
