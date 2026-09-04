#!/usr/bin/env python3
"""RUST-141 detached availability and fail-closed journal selftest."""
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
import rust_138_rust137_checkpoint_monitor_verify as monitor_verify
import rust_141_rust138_checkpoint_monitor_rotation_journal_verify as journal_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 302:
        raise SystemExit(
            "usage: rust_141_rust138_checkpoint_monitor_rotation_journal_selftest.py "
            "... FINAL_CHECKPOINT FORK_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 298:
        raise AssertionError("unexpected RUST-141 selftest base path count")

    journal_verify.verify(*base, source_sha, required_floor)

    monitored_checkpoint_raw, monitored_checkpoint = floor_verify.load_canonical(
        base[286], "RUST-137 final monitor rotation checkpoint"
    )
    target = monitor_verify.checkpoint_target(monitored_checkpoint_raw, monitored_checkpoint["statement"])
    old_bundle_raw, _ = floor_verify.load_canonical(base[287], "RUST-141 old monitor bundle")
    first_rotation_raw, _ = floor_verify.load_canonical(base[288], "RUST-141 first rotation")
    first_auth_raw, _ = floor_verify.load_canonical(base[289], "RUST-141 first auth")
    first_successor_raw, _ = floor_verify.load_canonical(base[290], "RUST-141 first successor")
    second_rotation_raw, _ = floor_verify.load_canonical(base[291], "RUST-141 second rotation")
    second_auth_raw, _ = floor_verify.load_canonical(base[292], "RUST-141 second auth")
    final_bundle_raw, _ = floor_verify.load_canonical(base[293], "RUST-141 final bundle")
    entries = journal_verify.expected_entries(
        old_bundle_raw, first_rotation_raw, first_auth_raw, first_successor_raw,
        second_rotation_raw, second_auth_raw, final_bundle_raw,
    )

    prefix_journal_raw, prefix_journal = floor_verify.load_canonical(base[294], "RUST-141 prefix journal")
    prefix_checkpoint_raw, prefix_checkpoint = floor_verify.load_canonical(base[295], "RUST-141 prefix checkpoint")
    final_journal_raw, final_journal = floor_verify.load_canonical(base[296], "RUST-141 final journal")
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(base[297], "RUST-141 final checkpoint")
    fork_raw, fork_checkpoint = floor_verify.load_canonical(fork_path, "RUST-141 observed fork checkpoint")

    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw, material_verify.canonical(entries[1]), 1,
        journal_verify.rotation1_verify.new_monitor_set(), None, 2, target, source_sha,
    )
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw, material_verify.canonical(entries[2]), 2,
        journal_verify.rotation2_verify.final_monitor_set(),
        journal_verify.sha256(prefix_checkpoint_raw), 3, target, source_sha,
    )

    prefix_ok = 0
    for subset in itertools.combinations(prefix_checkpoint["monitors"], journal_verify.THRESHOLD):
        candidate = copy.deepcopy(prefix_checkpoint)
        candidate["monitors"] = list(subset)
        journal_verify.validate_checkpoint(
            candidate, prefix_journal_raw, prefix_statement,
            journal_verify.rotation1_verify.NEW_PINNED_MONITORS, "prefix subset",
        )
        prefix_ok += 1
    if prefix_ok != 3:
        raise AssertionError("unexpected RUST-141 prefix subset count")
    print("[GREEN] RUST-141 prefix checkpoint availability: 3/3 valid two-monitor subsets accepted")

    final_ok = 0
    for subset in itertools.combinations(final_checkpoint["monitors"], journal_verify.THRESHOLD):
        candidate = copy.deepcopy(final_checkpoint)
        candidate["monitors"] = list(subset)
        journal_verify.validate_checkpoint(
            candidate, final_journal_raw, final_statement,
            journal_verify.rotation2_verify.FINAL_PINNED_MONITORS, "final subset",
        )
        final_ok += 1
    if final_ok != 3:
        raise AssertionError("unexpected RUST-141 final subset count")
    print("[GREEN] RUST-141 final checkpoint availability: 3/3 valid two-monitor subsets accepted")

    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        def run_with(index: int, path: Path) -> None:
            paths = list(base)
            paths[index] = path
            journal_verify.verify(*paths, source_sha, required_floor)

        value = copy.deepcopy(prefix_journal); value["entries"][0]["monitor_set_sha256"] = "0" * 64
        fail("prefix-genesis-set-rewrite", lambda: run_with(294, write("a.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["entries"][1]["rotation_sha256"] = "0" * 64
        fail("prefix-first-rotation-digest", lambda: run_with(294, write("b.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["entries"][1]["rotation_auth_sha256"] = "0" * 64
        fail("prefix-first-auth-digest", lambda: run_with(294, write("c.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["monitored_checkpoint_sha256"] = "0" * 64
        fail("prefix-monitored-checkpoint", lambda: run_with(294, write("d.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["monitored_checkpoint_statement_sha256"] = "0" * 64
        fail("prefix-monitored-statement", lambda: run_with(294, write("e.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["observed_target_sha256"] = "0" * 64
        fail("prefix-observed-target", lambda: run_with(294, write("f.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["activation_source_commit"] = "0" * 40
        fail("prefix-source", lambda: run_with(294, write("g.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["production"] = True
        fail("prefix-production", lambda: run_with(294, write("h.json", value))); cases += 1

        value = copy.deepcopy(final_journal); value["entries"] = value["entries"][:2]
        fail("final-entry-truncation", lambda: run_with(296, write("i.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][0]["monitor_bundle_sha256"] = "0" * 64
        fail("final-prefix-rewrite", lambda: run_with(296, write("j.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["sequence"] = 1
        fail("final-sequence-rollback", lambda: run_with(296, write("k.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["predecessor_entry_sha256"] = "0" * 64
        fail("final-predecessor-entry", lambda: run_with(296, write("l.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_sha256"] = "0" * 64
        fail("final-rotation-digest", lambda: run_with(296, write("m.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_auth_sha256"] = "0" * 64
        fail("final-rotation-auth-digest", lambda: run_with(296, write("n.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["monitor_bundle_sha256"] = "0" * 64
        fail("final-monitor-bundle", lambda: run_with(296, write("o.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["cumulative_revoked_monitor_ids"] = [journal_verify.rotation1_verify.REVOKED_MONITOR_ID]
        fail("final-revocation-omission", lambda: run_with(296, write("p.json", value))); cases += 1

        value = copy.deepcopy(prefix_checkpoint); value["threshold"] = 1
        fail("prefix-threshold", lambda: run_with(295, write("q.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["monitors"] = value["monitors"][:1]
        fail("prefix-below-threshold", lambda: run_with(295, write("r.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["monitors"] = [value["monitors"][0], copy.deepcopy(value["monitors"][0])]
        fail("prefix-duplicate", lambda: run_with(295, write("s.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint)
        sig = bytearray(material_verify.decode_signature(value["monitors"][0]["signature"])); sig[0] ^= 1
        value["monitors"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        fail("prefix-signature", lambda: run_with(295, write("t.json", value))); cases += 1

        value = copy.deepcopy(final_checkpoint); value["statement"]["previous_checkpoint_sha256"] = "0" * 64
        fail("final-previous-checkpoint", lambda: run_with(297, write("u.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["head_entry_sha256"] = "0" * 64
        fail("final-head-entry", lambda: run_with(297, write("v.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["monitored_checkpoint_sha256"] = "0" * 64
        fail("final-monitored-checkpoint", lambda: run_with(297, write("w.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["monitored_checkpoint_statement_sha256"] = "0" * 64
        fail("final-monitored-statement", lambda: run_with(297, write("x.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["observed_target_sha256"] = "0" * 64
        fail("final-observed-target", lambda: run_with(297, write("y.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["activation_source_commit"] = "0" * 40
        fail("final-source", lambda: run_with(297, write("z.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["production"] = True
        fail("final-production", lambda: run_with(297, write("aa.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["monitor_set_sequence"] = 1
        fail("final-monitor-set-sequence", lambda: run_with(297, write("ab.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["monitor_set_sha256"] = "0" * 64
        fail("final-monitor-set-digest", lambda: run_with(297, write("ac.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["threshold"] = 1
        fail("final-threshold", lambda: run_with(297, write("ad.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["monitors"] = value["monitors"][:1]
        fail("final-below-threshold", lambda: run_with(297, write("ae.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint)
        sig = bytearray(material_verify.decode_signature(value["monitors"][-1]["signature"])); sig[-1] ^= 1
        value["monitors"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        fail("final-signature", lambda: run_with(297, write("af.json", value))); cases += 1

        noncanonical_journal = root / "noncanonical-journal.json"
        noncanonical_journal.write_text(json.dumps(final_journal, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-final-journal", lambda: run_with(296, noncanonical_journal)); cases += 1
        noncanonical_checkpoint = root / "noncanonical-checkpoint.json"
        noncanonical_checkpoint.write_text(json.dumps(final_checkpoint, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-final-checkpoint", lambda: run_with(297, noncanonical_checkpoint)); cases += 1

        fail(
            "observed-valid-same-parent-monitor-rotation-journal-fork",
            lambda: journal_verify.reject_observed_fork(
                final_checkpoint_raw, final_checkpoint, fork_raw, fork_checkpoint,
                final_journal_raw, journal_verify.rotation2_verify.FINAL_PINNED_MONITORS,
            ),
        ); cases += 1

    if cases != 35:
        raise AssertionError(f"unexpected RUST-141 selftest case count: {cases}")
    print("RUST-141 monitor rotation journal fail-closed contract: 35/35 expected cases passed")


if __name__ == "__main__":
    main()
