#!/usr/bin/env python3
"""RUST-082 detached availability and fail-closed monitor selftest."""
from __future__ import annotations

import base64
import copy
import itertools
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_verify as rotation2_verify
import rust_081_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_verify as journal_verify
import rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify as monitor_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 138:
        raise SystemExit(
            "usage: rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_selftest.py "
            "... MONITOR_BUNDLE FORK_MONITOR_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_bundle_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 134:
        raise AssertionError("unexpected RUST-082 selftest base path count")

    monitor_verify.verify(*base, source_sha, required_floor)

    final_journal_raw, _ = floor_verify.load_canonical(
        base[131], "RUST-081 final observer rotation journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base[132], "RUST-081 final observer rotation checkpoint"
    )
    final_statement = journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_OBSERVERS,
        "RUST-082 selftest canonical",
    )
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_statement)
    _, bundle = floor_verify.load_canonical(base[133], "RUST-082 monitor bundle")
    _, fork_bundle = floor_verify.load_canonical(
        fork_bundle_path, "RUST-082 observed-fork monitor bundle"
    )

    availability = 0
    for subset in itertools.combinations(bundle["reports"], monitor_verify.THRESHOLD):
        candidate = copy.deepcopy(bundle)
        candidate["reports"] = list(subset)
        monitor_verify.validate_bundle(candidate, target)
        availability += 1
    if availability != 3:
        raise AssertionError("unexpected RUST-082 monitor subset count")
    print("[GREEN] RUST-082 monitor availability: 3/3 valid two-monitor subsets accepted")

    fork_checkpoint_raw, fork_checkpoint = floor_verify.load_canonical(
        Path("/tmp/axven-rust081-observed-fork-observer-rotation-checkpoint.json"),
        "RUST-081 observed fork checkpoint",
    )
    monitor_verify.validate_observed_fork_evidence(
        fork_bundle,
        target,
        fork_checkpoint_raw,
        fork_checkpoint,
        final_journal_raw,
    )
    print("[GREEN] RUST-082 signed observed same-parent fork evidence validated")

    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        def run_bundle(value: dict, name: str) -> None:
            paths = list(base)
            paths[133] = write(name, value)
            monitor_verify.verify(*paths, source_sha, required_floor)

        value = copy.deepcopy(bundle); value["schema"] = "bad"
        fail("bundle-schema", lambda: run_bundle(value, "a.json")); cases += 1
        value = copy.deepcopy(bundle); value["threshold"] = 1
        fail("threshold-downgrade", lambda: run_bundle(value, "b.json")); cases += 1
        value = copy.deepcopy(bundle); value["reports"] = value["reports"][:1]
        fail("below-threshold", lambda: run_bundle(value, "c.json")); cases += 1
        value = copy.deepcopy(bundle); value["reports"][1] = copy.deepcopy(value["reports"][0])
        fail("duplicate-monitor", lambda: run_bundle(value, "d.json")); cases += 1
        value = copy.deepcopy(bundle); value["reports"] = list(reversed(value["reports"]))
        fail("unsorted-monitors", lambda: run_bundle(value, "e.json")); cases += 1
        value = copy.deepcopy(bundle); value["production"] = True
        fail("bundle-production", lambda: run_bundle(value, "f.json")); cases += 1

        value = copy.deepcopy(bundle); value["reports"][0]["schema"] = "bad"
        fail("report-schema", lambda: run_bundle(value, "g.json")); cases += 1
        value = copy.deepcopy(bundle); value["reports"][0]["algorithm"] = "bad"
        fail("report-algorithm", lambda: run_bundle(value, "h.json")); cases += 1
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["schema"] = "bad"
        fail("statement-schema", lambda: run_bundle(value, "i.json")); cases += 1
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["production"] = True
        fail("statement-production", lambda: run_bundle(value, "j.json")); cases += 1
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["monitor_id"] = "unknown"
        fail("unknown-monitor", lambda: run_bundle(value, "k.json")); cases += 1
        value = copy.deepcopy(bundle)
        sig = bytearray(material_verify.decode_signature(value["reports"][0]["signature"]))
        sig[0] ^= 1
        value["reports"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        fail("report-signature", lambda: run_bundle(value, "l.json")); cases += 1

        target_fields = [
            ("monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_checkpoint_sha256", "0" * 64),
            ("monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_checkpoint_statement_sha256", "1" * 64),
            ("observer_set_sequence", 1),
            ("observer_set_sha256", "2" * 64),
            ("entry_count", 2),
            ("journal_sha256", "3" * 64),
            ("head_entry_sha256", "4" * 64),
            ("previous_checkpoint_sha256", "5" * 64),
            ("observed_checkpoint_sha256", "6" * 64),
            ("observed_checkpoint_statement_sha256", "7" * 64),
            ("observed_target_sha256", "8" * 64),
            ("activation_source_commit", "0" * 40),
        ]
        for idx, (field, replacement) in enumerate(target_fields):
            value = copy.deepcopy(bundle)
            value["reports"][0]["statement"][field] = replacement
            fail(f"target-{field}", lambda v=value, n=f"m{idx}.json": run_bundle(v, n))
            cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        paths = list(base); paths[133] = noncanonical
        fail(
            "noncanonical-monitor-bundle",
            lambda: monitor_verify.verify(*paths, source_sha, required_floor),
        ); cases += 1

        paths = list(base); paths[133] = base[132]
        fail(
            "rust081-checkpoint-replay",
            lambda: monitor_verify.verify(*paths, source_sha, required_floor),
        ); cases += 1

        paths = list(base); paths[133] = fork_bundle_path
        fail(
            "signed-same-parent-fork-bundle",
            lambda: monitor_verify.verify(*paths, source_sha, required_floor),
        ); cases += 1

    if cases != 27:
        raise AssertionError(f"unexpected RUST-082 fail-closed case count: {cases}")
    print("RUST-082 RUST-081 observer-rotation-journal monitor fail-closed contract: 27/27 expected cases passed")


if __name__ == "__main__":
    main()
