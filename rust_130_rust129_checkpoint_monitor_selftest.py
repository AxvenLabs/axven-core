#!/usr/bin/env python3
"""RUST-130 detached availability and fail-closed monitor selftest."""
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
import rust_129_rust126_checkpoint_monitor_rotation_journal_verify as journal_verify
import rust_130_rust129_checkpoint_monitor_verify as monitor_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def replacement_for(field: str):
    if field == "activation_source_commit":
        return "0" * 40
    if field == "monitor_set_sequence":
        return 1
    if field == "entry_count":
        return 2
    return "0" * 64


def main() -> None:
    if len(sys.argv) != 270:
        raise SystemExit(
            "usage: rust_130_rust129_checkpoint_monitor_selftest.py "
            "... MONITOR_BUNDLE FORK_MONITOR_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_bundle_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 266:
        raise AssertionError("unexpected RUST-130 selftest base path count")

    monitor_verify.verify(*base, source_sha, required_floor)

    final_journal_raw, _ = floor_verify.load_canonical(
        base[263], "RUST-129 final monitor rotation journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base[264], "RUST-129 final monitor rotation checkpoint"
    )
    final_statement = journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        journal_verify.rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-130 selftest canonical",
    )
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_statement)
    _, bundle = floor_verify.load_canonical(base[265], "RUST-130 monitor bundle")
    _, fork_bundle = floor_verify.load_canonical(
        fork_bundle_path, "RUST-130 observed-fork monitor bundle"
    )

    availability = 0
    for subset in itertools.combinations(bundle["reports"], monitor_verify.THRESHOLD):
        candidate = copy.deepcopy(bundle)
        candidate["reports"] = list(subset)
        monitor_verify.validate_bundle(candidate, target)
        availability += 1
    if availability != 3:
        raise AssertionError("unexpected RUST-130 monitor subset count")
    print("[GREEN] RUST-130 monitor availability: 3/3 valid two-monitor subsets accepted")

    fork_checkpoint_raw, fork_checkpoint = floor_verify.load_canonical(
        Path("/tmp/axven-rust129-observed-fork-monitor-rotation-checkpoint.json"),
        "RUST-129 observed fork checkpoint",
    )
    monitor_verify.validate_observed_fork_evidence(
        fork_bundle,
        target,
        fork_checkpoint_raw,
        fork_checkpoint,
        final_journal_raw,
    )
    print("[GREEN] RUST-130 signed observed same-parent fork evidence validated")

    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        def run_bundle(value: dict, name: str) -> None:
            paths = list(base)
            paths[265] = write(name, value)
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
        fail("unsorted-monitor", lambda: run_bundle(value, "e.json")); cases += 1
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

        for idx, field in enumerate(sorted(monitor_verify.TARGET_KEYS)):
            value = copy.deepcopy(bundle)
            value["reports"][0]["statement"][field] = replacement_for(field)
            fail(
                f"target-{field}",
                lambda v=value, n=f"m{idx}.json": run_bundle(v, n),
            )
            cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        paths = list(base); paths[265] = noncanonical
        fail(
            "noncanonical-monitor-bundle",
            lambda: monitor_verify.verify(*paths, source_sha, required_floor),
        ); cases += 1

        paths = list(base); paths[265] = base[264]
        fail(
            "rust129-checkpoint-replay",
            lambda: monitor_verify.verify(*paths, source_sha, required_floor),
        ); cases += 1

        paths = list(base); paths[265] = fork_bundle_path
        fail(
            "signed-same-parent-fork-bundle",
            lambda: monitor_verify.verify(*paths, source_sha, required_floor),
        ); cases += 1

    if cases != 27:
        raise AssertionError(f"unexpected RUST-130 fail-closed case count: {cases}")
    print("RUST-130 RUST-129 journal checkpoint monitor fail-closed contract: 27/27 expected cases passed")


if __name__ == "__main__":
    main()
