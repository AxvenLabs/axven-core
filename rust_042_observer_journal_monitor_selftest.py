#!/usr/bin/env python3
"""RUST-042 detached availability/fail-closed contract."""
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
import rust_042_observer_journal_monitor_verify as monitor_verify


def write_canonical(path: Path, value: dict) -> None:
    path.write_bytes(material_verify.canonical(value))


def invoke(paths: list[Path], source: str, floor: str) -> None:
    monitor_verify.verify(*paths, source, floor)


def expect_reject(label: str, paths: list[Path], source: str, floor: str, mutate) -> None:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "bundle.json"
        _, value = floor_verify.load_canonical(paths[-1], "monitor bundle")
        changed = copy.deepcopy(value)
        mutate(changed)
        write_canonical(out, changed)
        trial = paths[:-1] + [out]
        try:
            invoke(trial, source, floor)
        except Exception:
            print(f"[GREEN] mutation rejected: {label}")
            return
        raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 29:
        raise SystemExit("usage: rust_042_observer_journal_monitor_selftest.py ... MONITOR_BUNDLE FORK_MONITOR_BUNDLE FORK_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR")
    source = sys.argv[-2]
    floor = sys.argv[-1]
    # Explicit indexing keeps CLI readable: all base paths, canonical bundle, fork bundle, fork checkpoint, source, floor.
    all_paths = [Path(value) for value in sys.argv[1:-2]]
    base = all_paths[:23]
    canonical_bundle_path = all_paths[23]
    fork_bundle_path = all_paths[24]
    fork_checkpoint_path = all_paths[25]
    verify_paths = base + [canonical_bundle_path]

    invoke(verify_paths, source, floor)
    _, canonical_bundle = floor_verify.load_canonical(canonical_bundle_path, "monitor bundle")
    accepted = 0
    for rows in itertools.combinations(canonical_bundle["reports"], monitor_verify.THRESHOLD):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "subset.json"
            subset = copy.deepcopy(canonical_bundle)
            subset["reports"] = list(rows)
            write_canonical(p, subset)
            invoke(base + [p], source, floor)
            accepted += 1
    if accepted != 3:
        raise AssertionError("unexpected monitor subset count")
    print("[GREEN] RUST-042 monitor availability: 3/3 valid two-monitor subsets accepted")

    mutations = [
        ("bundle-schema", lambda b: b.__setitem__("schema", "bad")),
        ("threshold-downgrade", lambda b: b.__setitem__("threshold", 1)),
        ("bundle-production", lambda b: b.__setitem__("production", True)),
        ("below-threshold", lambda b: b.__setitem__("reports", b["reports"][:1])),
        ("duplicate-monitor", lambda b: b.__setitem__("reports", [b["reports"][0], copy.deepcopy(b["reports"][0])])),
        ("unsorted-monitor", lambda b: b.__setitem__("reports", list(reversed(b["reports"][:2])))),
        ("unknown-monitor", lambda b: b["reports"][0]["statement"].__setitem__("monitor_id", "unknown-monitor")),
        ("report-schema", lambda b: b["reports"][0].__setitem__("schema", "bad")),
        ("algorithm", lambda b: b["reports"][0].__setitem__("algorithm", "bad")),
        ("statement-schema", lambda b: b["reports"][0]["statement"].__setitem__("schema", "bad")),
        ("checkpoint-digest", lambda b: b["reports"][0]["statement"].__setitem__("checkpoint_sha256", "0" * 64)),
        ("observer-set-sequence", lambda b: b["reports"][0]["statement"].__setitem__("observer_set_sequence", 1)),
        ("observer-set-digest", lambda b: b["reports"][0]["statement"].__setitem__("observer_set_sha256", "0" * 64)),
        ("journal-digest", lambda b: b["reports"][0]["statement"].__setitem__("journal_sha256", "0" * 64)),
        ("head-entry", lambda b: b["reports"][0]["statement"].__setitem__("head_entry_sha256", "0" * 64)),
        ("previous-checkpoint", lambda b: b["reports"][0]["statement"].__setitem__("previous_checkpoint_sha256", "0" * 64)),
        ("checkpoint-statement", lambda b: b["reports"][0]["statement"].__setitem__("checkpoint_statement_sha256", "0" * 64)),
        ("source", lambda b: b["reports"][0]["statement"].__setitem__("activation_source_commit", "0" * 40)),
        ("statement-production", lambda b: b["reports"][0]["statement"].__setitem__("production", True)),
        ("signature", lambda b: b["reports"][0].__setitem__("signature", base64.b64encode(b"\x00" * 64).decode("ascii"))),
    ]
    for label, mutate in mutations:
        expect_reject(label, verify_paths, source, floor, mutate)

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "noncanonical.json"
        p.write_text(json.dumps(canonical_bundle, indent=2), encoding="utf-8")
        try:
            invoke(base + [p], source, floor)
        except Exception:
            print("[GREEN] mutation rejected: noncanonical-monitor-bundle")
        else:
            raise AssertionError("noncanonical monitor bundle accepted")

    final_journal_raw, _ = floor_verify.load_canonical(base[21], "final observer journal")
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(base[22], "final observer checkpoint")
    canonical_statement = monitor_verify.journal_verify.validate_checkpoint_envelope(
        final_checkpoint, final_journal_raw, monitor_verify.rotation2_verify.FINAL_PINNED_OBSERVERS, "canonical monitored"
    )
    canonical_target = monitor_verify.checkpoint_target(final_checkpoint_raw, canonical_statement)
    fork_checkpoint_raw, fork_checkpoint_value = floor_verify.load_canonical(fork_checkpoint_path, "observed fork checkpoint")
    _, fork_bundle_value = floor_verify.load_canonical(fork_bundle_path, "observed fork monitor bundle")
    monitor_verify.validate_observed_fork_evidence(
        fork_bundle_value, canonical_target, fork_checkpoint_raw, fork_checkpoint_value, final_journal_raw
    )
    print("[GREEN] valid signed RUST-041 fork is bound by a signed RUST-042 monitor report")
    try:
        invoke(base + [fork_bundle_path], source, floor)
    except AssertionError as exc:
        if "observed monitor same-parent observer-journal fork" not in str(exc):
            raise
        print("[GREEN] mutation rejected: observed-valid-same-parent-monitor-split-view")
    else:
        raise AssertionError("valid signed monitor split view unexpectedly accepted")

    print(f"RUST-042 observer-journal monitor fail-closed contract: {len(mutations) + 2}/22 expected cases passed")


if __name__ == "__main__":
    main()
