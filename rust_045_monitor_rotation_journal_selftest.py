#!/usr/bin/env python3
"""RUST-045 availability and fail-closed selftest for monitor rotation journal continuity."""
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
import rust_043_monitor_set_rotation_verify as rotation1_verify
import rust_044_multistep_monitor_rotation_verify as rotation2_verify
import rust_045_monitor_rotation_journal_verify as journal_verify


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 38:
        raise SystemExit("usage: rust_045_monitor_rotation_journal_selftest.py ... FINAL_MON_CHECKPOINT FORK_MON_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR")
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha = sys.argv[-2]
    required_floor = sys.argv[-1]
    if len(base) != 34:
        raise AssertionError("unexpected RUST-045 base path count")

    journal_verify.verify(*base, source_sha, required_floor)

    old_bundle_raw, _ = floor_verify.load_canonical(base[23], "old monitor bundle")
    first_rotation_raw, _ = floor_verify.load_canonical(base[24], "first monitor rotation")
    first_auth_raw, _ = floor_verify.load_canonical(base[25], "first monitor auth")
    first_successor_raw, _ = floor_verify.load_canonical(base[26], "first monitor successor")
    second_rotation_raw, _ = floor_verify.load_canonical(base[27], "second monitor rotation")
    second_auth_raw, _ = floor_verify.load_canonical(base[28], "second monitor auth")
    final_bundle_raw, _ = floor_verify.load_canonical(base[29], "final monitor bundle")
    entries = journal_verify.expected_entries(
        old_bundle_raw, first_rotation_raw, first_auth_raw, first_successor_raw,
        second_rotation_raw, second_auth_raw, final_bundle_raw,
    )
    prefix_journal_raw, prefix_journal = floor_verify.load_canonical(base[30], "prefix monitor journal")
    prefix_checkpoint_raw, prefix_checkpoint = floor_verify.load_canonical(base[31], "prefix monitor checkpoint")
    final_journal_raw, final_journal = floor_verify.load_canonical(base[32], "final monitor journal")
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(base[33], "final monitor checkpoint")
    fork_raw, fork_checkpoint = floor_verify.load_canonical(fork_path, "fork monitor checkpoint")

    observer_checkpoint_digest = prefix_journal["observer_checkpoint_sha256"]
    statement_digest = prefix_journal["checkpoint_statement_sha256"]
    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw, material_verify.canonical(entries[1]), 1, rotation1_verify.new_monitor_set(),
        None, 2, observer_checkpoint_digest, statement_digest, source_sha,
    )
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw, material_verify.canonical(entries[2]), 2, rotation2_verify.final_monitor_set(),
        journal_verify.sha256(prefix_checkpoint_raw), 3, observer_checkpoint_digest, statement_digest, source_sha,
    )

    prefix_ok = 0
    for subset in itertools.combinations(prefix_checkpoint["monitors"], journal_verify.THRESHOLD):
        candidate = copy.deepcopy(prefix_checkpoint)
        candidate["monitors"] = list(subset)
        journal_verify.validate_checkpoint(
            candidate, prefix_journal_raw, prefix_statement,
            rotation1_verify.NEW_PINNED_MONITORS, "prefix subset",
        )
        prefix_ok += 1
    if prefix_ok != 3:
        raise AssertionError("unexpected prefix monitor availability subset count")
    print("[GREEN] RUST-045 prefix monitor checkpoint availability: 3/3 valid two-monitor subsets accepted")

    final_ok = 0
    for subset in itertools.combinations(final_checkpoint["monitors"], journal_verify.THRESHOLD):
        candidate = copy.deepcopy(final_checkpoint)
        candidate["monitors"] = list(subset)
        journal_verify.validate_checkpoint(
            candidate, final_journal_raw, final_statement,
            rotation2_verify.FINAL_PINNED_MONITORS, "final subset",
        )
        final_ok += 1
    if final_ok != 3:
        raise AssertionError("unexpected final monitor availability subset count")
    print("[GREEN] RUST-045 final monitor checkpoint availability: 3/3 valid two-monitor subsets accepted")

    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        def run_with(index: int, path: Path) -> None:
            paths = list(base)
            paths[index] = path
            journal_verify.verify(*paths, source_sha, required_floor)

        value = copy.deepcopy(prefix_journal); value["entries"][0]["monitor_set_sha256"] = "0" * 64
        expect_failure("prefix-genesis-set-rewrite", lambda: run_with(30, write_obj("a.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["activation_source_commit"] = "0" * 40
        expect_failure("prefix-source", lambda: run_with(30, write_obj("b.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["observer_checkpoint_sha256"] = "0" * 64
        expect_failure("prefix-observer-checkpoint-binding", lambda: run_with(30, write_obj("c.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["checkpoint_statement_sha256"] = "0" * 64
        expect_failure("prefix-checkpoint-statement-binding", lambda: run_with(30, write_obj("d.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["production"] = True
        expect_failure("prefix-production", lambda: run_with(30, write_obj("e.json", value))); cases += 1

        value = copy.deepcopy(final_journal); value["entries"] = value["entries"][:2]
        expect_failure("final-entry-truncation", lambda: run_with(32, write_obj("f.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][0]["monitor_bundle_sha256"] = "0" * 64
        expect_failure("final-prefix-rewrite", lambda: run_with(32, write_obj("g.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["sequence"] = 1
        expect_failure("final-sequence-rollback", lambda: run_with(32, write_obj("h.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["predecessor_entry_sha256"] = "0" * 64
        expect_failure("final-predecessor-entry", lambda: run_with(32, write_obj("i.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_sha256"] = "0" * 64
        expect_failure("final-rotation-digest", lambda: run_with(32, write_obj("j.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_auth_sha256"] = "0" * 64
        expect_failure("final-rotation-auth-digest", lambda: run_with(32, write_obj("k.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["monitor_bundle_sha256"] = "0" * 64
        expect_failure("final-monitor-bundle-digest", lambda: run_with(32, write_obj("l.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["cumulative_revoked_monitor_ids"] = [rotation1_verify.REVOKED_MONITOR_ID]
        expect_failure("final-revocation-omission", lambda: run_with(32, write_obj("m.json", value))); cases += 1

        value = copy.deepcopy(prefix_checkpoint); value["threshold"] = 1
        expect_failure("prefix-threshold-downgrade", lambda: run_with(31, write_obj("n.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["monitors"] = value["monitors"][:1]
        expect_failure("prefix-below-threshold", lambda: run_with(31, write_obj("o.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["monitors"] = [value["monitors"][0], copy.deepcopy(value["monitors"][0])]
        expect_failure("prefix-duplicate-monitor", lambda: run_with(31, write_obj("p.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); sig = bytearray(base64.b64decode(value["monitors"][0]["signature"])); sig[0] ^= 1; value["monitors"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("prefix-signature", lambda: run_with(31, write_obj("q.json", value))); cases += 1

        value = copy.deepcopy(final_checkpoint); value["statement"]["previous_checkpoint_sha256"] = "0" * 64
        expect_failure("final-previous-checkpoint", lambda: run_with(33, write_obj("r.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["head_entry_sha256"] = "0" * 64
        expect_failure("final-head-entry", lambda: run_with(33, write_obj("s.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["observer_checkpoint_sha256"] = "0" * 64
        expect_failure("final-observer-checkpoint-binding", lambda: run_with(33, write_obj("t.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["checkpoint_statement_sha256"] = "0" * 64
        expect_failure("final-checkpoint-statement-binding", lambda: run_with(33, write_obj("u.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["activation_source_commit"] = "0" * 40
        expect_failure("final-source", lambda: run_with(33, write_obj("v.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["production"] = True
        expect_failure("final-production", lambda: run_with(33, write_obj("w.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["threshold"] = 1
        expect_failure("final-threshold-downgrade", lambda: run_with(33, write_obj("x.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["monitors"] = value["monitors"][:1]
        expect_failure("final-below-threshold", lambda: run_with(33, write_obj("y.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); sig = bytearray(base64.b64decode(value["monitors"][-1]["signature"])); sig[-1] ^= 1; value["monitors"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("final-signature", lambda: run_with(33, write_obj("z.json", value))); cases += 1

        noncanonical_journal = root / "noncanonical-journal.json"
        noncanonical_journal.write_text(json.dumps(final_journal, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final-journal", lambda: run_with(32, noncanonical_journal)); cases += 1
        noncanonical_checkpoint = root / "noncanonical-checkpoint.json"
        noncanonical_checkpoint.write_text(json.dumps(final_checkpoint, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final-checkpoint", lambda: run_with(33, noncanonical_checkpoint)); cases += 1

        expect_failure(
            "observed-valid-same-parent-monitor-rotation-journal-fork",
            lambda: journal_verify.reject_observed_fork(
                final_checkpoint_raw, final_checkpoint, fork_raw, fork_checkpoint,
                final_journal_raw, rotation2_verify.FINAL_PINNED_MONITORS,
            ),
        ); cases += 1

    if cases != 29:
        raise AssertionError(f"unexpected RUST-045 fail-closed case count: {cases}")
    print("RUST-045 monitor rotation journal fail-closed contract: 29/29 expected cases passed")


if __name__ == "__main__":
    main()
