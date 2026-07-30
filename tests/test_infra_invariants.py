"""Static invariants that require values unknown during the first plan."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DETECTION_MODULE = ROOT / "infra" / "modules" / "detection" / "main.tf"


def test_dead_letter_queue_uses_only_customer_managed_kms() -> None:
    module = DETECTION_MODULE.read_text(encoding="utf-8")

    assert "kms_master_key_id                 = var.kms_key_arn" in module
    assert "sqs_managed_sse_enabled" not in _active_lines(module)


def _active_lines(source: str) -> str:
    return "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
