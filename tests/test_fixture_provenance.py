"""Provenance guard.

This repository's claim is "detections are tested against recorded CloudTrail
events". Right now that is not true — every fixture was written from AWS
documentation. That is a fine starting point and a bad thing to forget, so the
distinction is machine-checked rather than left to a paragraph in a README:

* every fixture declares its provenance
* a fixture cannot claim to be verified while its detection's metadata says the
  detection has no verified fixtures
* a detection cannot claim verified fixtures while any of its fixtures is still
  documentation-derived

Which means the day the real events are captured, the marker has to be updated
in both places or CI fails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tests.conftest import DETECTION_ROOT, FIXTURE_ROOT, load_json

VALID_STATUSES = {"derived-from-documentation", "verified"}

FIXTURES = sorted(FIXTURE_ROOT.rglob("*.json"))
DETECTIONS = sorted(path for path in DETECTION_ROOT.iterdir() if path.is_dir())


def _ids(paths: list[Path]) -> list[str]:
    return [path.name for path in paths]


def test_there_are_fixtures_at_all() -> None:
    assert FIXTURES, "no fixtures found — the provenance guard would pass vacuously"


@pytest.mark.parametrize("path", FIXTURES, ids=_ids(FIXTURES))
def test_every_fixture_declares_its_provenance(path: Path) -> None:
    marker = load_json(path).get("_pac_fixture")

    assert marker is not None, f"{path.name} has no _pac_fixture marker"
    assert marker["status"] in VALID_STATUSES
    assert isinstance(marker["verified_against_live_event"], bool)
    assert marker["source"], "say where the shape came from"


@pytest.mark.parametrize("path", FIXTURES, ids=_ids(FIXTURES))
def test_provenance_status_and_flag_agree(path: Path) -> None:
    marker = load_json(path)["_pac_fixture"]

    assert marker["verified_against_live_event"] is (marker["status"] == "verified")


@pytest.mark.parametrize("path", FIXTURES, ids=_ids(FIXTURES))
def test_unverified_fixtures_explain_how_to_capture_the_real_one(path: Path) -> None:
    marker = load_json(path)["_pac_fixture"]
    if marker["status"] == "verified":
        return

    assert marker.get("capture"), (
        f"{path.name} is documentation-derived and does not say how to capture the real event"
    )


@pytest.mark.parametrize("detection", DETECTIONS, ids=_ids(DETECTIONS))
def test_detection_metadata_matches_its_fixtures(detection: Path) -> None:
    metadata = yaml.safe_load((detection / "metadata.yaml").read_text(encoding="utf-8"))
    claimed = bool(metadata["fixture_verified_against_live_event"])

    fixtures = [
        load_json(path)
        for category in ("cloudtrail", "guardduty")
        for path in (FIXTURE_ROOT / category / detection.name).glob("*.json")
    ]
    assert fixtures, f"{detection.name} has no fixtures"

    actual = all(item["_pac_fixture"]["verified_against_live_event"] for item in fixtures)
    assert claimed is actual, (
        f"{detection.name}/metadata.yaml claims fixture_verified_against_live_event="
        f"{claimed} but its fixtures say {actual}"
    )


@pytest.mark.parametrize("detection", DETECTIONS, ids=_ids(DETECTIONS))
def test_pattern_is_valid_json_and_metadata_is_consistent(detection: Path) -> None:
    pattern = json.loads((detection / "pattern.json").read_text(encoding="utf-8"))
    metadata = yaml.safe_load((detection / "metadata.yaml").read_text(encoding="utf-8"))

    assert metadata["id"] == detection.name
    assert metadata["package"] == detection.name.replace("-", "_")
    assert metadata["attack"], "a detection with no ATT&CK mapping is a rule, not a detection"
    assert pattern.get("source"), "every pattern must pin an event source"
