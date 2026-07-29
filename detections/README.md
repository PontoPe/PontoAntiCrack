# Detections

One directory per detection, named with the detection ID. Each holds the two
files that describe *what to watch for*; the code that decides what to do about
it lives in `remediations/<package>/`.

```
detections/<id>/
  pattern.json     the EventBridge event pattern
  metadata.yaml    ATT&CK mapping, severity, fixture provenance, known gaps
```

The ID is kebab-case (`s3-public`) everywhere — alerts, IAM, Terraform,
directory names. The Python package is the same string with underscores
(`s3_public`), because Python cannot import a hyphen. `metadata.yaml` records
the mapping and `scripts/check-detection-coverage.sh` enforces it (ADR-011).

## Patterns are deliberately coarse

An EventBridge pattern cannot evaluate a port range, parse a policy document, or
read the resulting state of a resource. `PutBucketPolicy` that opens a bucket
and `PutBucketPolicy` that closes one are the same event name.

So the pattern is a cheap filter and the handler is the decision. `sg-open` is
delivered an event for a rule opening 443 to the world and deliberately does
nothing with it — that path is tested, in
`tests/remediations/test_sg_open_handler.py::test_https_open_to_the_world_produces_no_plan`.

What the pattern *does* carry is anything that would otherwise cost an
invocation for nothing: failed calls (`errorCode` absent), read-only APIs,
non-world CIDRs, GuardDuty findings below MEDIUM.

## Adding one

CI fails unless all of this exists:

- `detections/<id>/pattern.json` and `metadata.yaml`
- `remediations/<pkg>/handler.py`, `policy.json`, `README.md`
- `tests/detections/test_<pkg>_pattern.py` — containing at least one
  `assert not matches`
- `tests/remediations/test_<pkg>_handler.py`
- at least two fixtures, one of them named `benign-*.json`
- a row in `docs/mitre-attack.md`

The `assert not matches` requirement is not bureaucracy. A pattern tested only
for what it catches passes CI forever while quietly matching every event in the
account, and the first person to find out is whoever gets paged by the
remediation storm.

## Fixture naming

| Prefix | Meaning |
|---|---|
| `benign-*` | The **pattern** must not match it. Failed calls, read-only APIs, internal CIDRs, low-severity findings. |
| anything else | The pattern matches. The handler may still decide to do nothing — `authorize-ingress-https-world.json` matches and is then correctly ignored. |

## Provenance

Every fixture carries a `_pac_fixture` marker declaring where its shape came
from. All of them currently say `derived-from-documentation`, and
`tests/test_fixture_provenance.py` fails if that ever silently stops being
recorded. See [`tests/fixtures/README.md`](../tests/fixtures/README.md).
