#!/usr/bin/env python3
"""RUST-150 static CI fan-out hardening policy."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VALIDATION = ROOT / ".github/workflows/validation.yml"
FUZZ = ROOT / ".github/workflows/fuzz-smoke.yml"
PERF = ROOT / ".github/workflows/perf-baseline.yml"
NATIVE = ROOT / ".github/workflows/native-rust149-checkpoint-monitor-rotation-journal.yml"
SELF = ROOT / ".github/workflows/native-rust150-ci-fanout-hardening.yml"
DOC = ROOT / "RUST_150.md"

EXPECTED = {
    VALIDATION: "ed3e90bfc3d96bf3e62f8ce95b5514faf13062b4",
    FUZZ: "b58475d67e5b662d2971f26642760906b9ff6316",
    PERF: "91cc3feea0b32634c4df9e16f4a720842621a4e7",
    NATIVE: "dfcaa986f53355ca130f86e463cd8ad608c69e61",
}

PINNED_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
PINNED_SETUP = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def text(path: Path) -> str:
    value = path.read_text(encoding="utf-8")
    if "\r" in value:
        raise AssertionError(f"CR forbidden: {path}")
    return value


def assert_common(name: str, value: str) -> None:
    if "permissions:\n  contents: read" not in value:
        raise AssertionError(f"{name}: read-only contents permission required")
    lower = value.lower()
    for forbidden in ("contents: write", "actions: write", "id-token: write", "packages: write", "pull-requests: write"):
        if forbidden in lower:
            raise AssertionError(f"{name}: write permission forbidden: {forbidden}")
    if PINNED_CHECKOUT not in value or PINNED_SETUP not in value:
        raise AssertionError(f"{name}: exact pinned checkout/setup-python actions required")
    if "persist-credentials: false" not in value:
        raise AssertionError(f"{name}: checkout credentials must not persist")


def assert_unfiltered_pr(name: str, value: str) -> None:
    marker = "  pull_request:\n"
    if marker not in value:
        raise AssertionError(f"{name}: pull_request trigger required")
    tail = value.split(marker, 1)[1]
    lines = tail.splitlines()
    if lines and lines[0].startswith("    "):
        raise AssertionError(f"{name}: filtered pull_request forbidden")


def event_paths(value: str, event: str) -> str:
    marker = f"  {event}:\n    paths:\n"
    if value.count(marker) != 1:
        raise AssertionError(f"RUST-149 active checkpoint: expected one {event}.paths block")
    tail = value.split(marker, 1)[1]
    lines = tail.splitlines()
    block: list[str] = []
    for line in lines:
        if line.startswith("  ") and not line.startswith("    "):
            break
        block.append(line)
    if not block:
        raise AssertionError(f"RUST-149 active checkpoint: empty {event}.paths block")
    return "\n".join(block) + "\n"


def assert_perf(value: str) -> None:
    if "name: Axven Performance Baseline" not in value or "  pull_request:\n" not in value:
        raise AssertionError("Performance: independent pull_request workflow required")
    if "python perf_001_baseline.py" not in value:
        raise AssertionError("Performance: baseline command missing")


def assert_native(value: str) -> None:
    required_global = (
        "name: Axven Native RUST-149 Checkpoint Monitor Rotation Journal",
        "python rust_149_rust146_checkpoint_monitor_rotation_journal_policy_spec.py",
    )
    for needle in required_global:
        if needle not in value:
            raise AssertionError(f"RUST-149 active checkpoint trigger/verification closure missing: {needle}")

    required_paths = (
        '- "requirements-ci-runtime-posix.lock"',
        '- "rust_*.py"',
        '- "RUST_*.md"',
        '- ".github/workflows/native-rust148-multistep-rust146-checkpoint-monitor-rotation.yml"',
        '- ".github/workflows/native-rust149-checkpoint-monitor-rotation-journal.yml"',
    )
    for event in ("push", "pull_request"):
        block = event_paths(value, event)
        for needle in required_paths:
            if needle not in block:
                raise AssertionError(f"RUST-149 active checkpoint {event}.paths closure missing: {needle}")


def check_texts(validation: str, fuzz: str, perf: str, native: str) -> None:
    names = {
        "validation": "name: Axven Validation",
        "fuzz": "name: Axven Fuzz Smoke",
        "perf": "name: Axven Performance Baseline",
        "native": "name: Axven Native RUST-149 Checkpoint Monitor Rotation Journal",
    }
    values = {"validation": validation, "fuzz": fuzz, "perf": perf, "native": native}
    for key, marker in names.items():
        if marker not in values[key]:
            raise AssertionError(f"{key}: expected independent workflow identity missing")
        assert_common(key, values[key])
    assert_unfiltered_pr("Validation", validation)
    assert_unfiltered_pr("Fuzz", fuzz)
    if "python run_full_validation.py" not in validation or "python security_tail_runner.py" not in validation:
        raise AssertionError("Validation: full validation/security tail coverage missing")
    if "python fuzz_001_smoke.py" not in fuzz or "fuzz_targets/fuzz_parser_crypto.py" not in fuzz:
        raise AssertionError("Fuzz: deterministic and coverage-guided lanes required")
    assert_perf(perf)
    assert_native(native)


def main() -> None:
    for path, expected in EXPECTED.items():
        actual = blob(path.read_bytes())
        if actual != expected:
            raise AssertionError(f"reviewed workflow blob changed: {path.name}: {actual} != {expected}")
    validation, fuzz, perf, native = map(text, (VALIDATION, FUZZ, PERF, NATIVE))
    check_texts(validation, fuzz, perf, native)
    self_workflow = text(SELF)
    for needle in (
        '"rust_*.py"', '"RUST_*.md"', '".github/workflows/*.yml"',
        '"run_full_validation.py"', '"security_tail_runner.py"', '"fuzz_*.py"',
        '"fuzz_targets/**"', '"perf_*.py"', '"requirements-*.lock"',
        "python rust_150_ci_fanout_policy_spec.py", "python rust_150_ci_fanout_selftest.py",
    ):
        if needle not in self_workflow:
            raise AssertionError(f"RUST-150 self workflow trigger/step missing: {needle}")
    assert_common("RUST-150", self_workflow)
    doc = text(DOC)
    for needle in ("CI fan-out hardening", "Production consensus remains Python-authoritative.", "non-production CI policy only"):
        if needle not in doc:
            raise AssertionError(f"RUST-150 doc boundary missing: {needle}")
    print("RUST-150 CI fan-out policy: GREEN (4 exact workflow blobs, independent gates, fail-closed triggers)")


if __name__ == "__main__":
    main()
