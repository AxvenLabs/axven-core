#!/usr/bin/env python3
"""RUST-065 availability and fail-closed selftest for observer rotation journal continuity."""
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
import rust_065_monitor_rotation_journal_observer_rotation_journal_verify as journal_verify


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 93:
        raise SystemExit(
            "usage: rust_065_monitor_rotation_journal_observer_rotation_journal_selftest.py "
            "... FINAL_CHECKPOINT FORK_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 89:
        raise AssertionError("unexpected RUST-065 base path count")

    journal_verify.verify(*base, source_sha, required_floor)

    monitored_checkpoint_raw, monitored_checkpoint = floor_verify.load_canonical(
        base[77], "final observer-rotation-journal monitor rotation checkpoint"
    )
    target = journal_verify.gossip_verify.canonical_target(
        monitored_checkpoint_raw, monitored_checkpoint, source_sha
    )
    old_bundle_raw, _ = floor_verify.load_canonical(base[78], "old observer bundle")
    first_rotation_raw, _ = floor_verify.load_canonical(base[79], "first observer rotation")
    first_auth_raw, _ = floor_verify.load_canonical(base[80], "first observer auth")
    first_successor_raw, _ = floor_verify.load_canonical(base[81], "first observer successor")
    second_rotation_raw, _ = floor_verify.load_canonical(base[82], "second observer rotation")
    second_auth_raw, _ = floor_verify.load_canonical(base[83], "second observer auth")
    final_bundle_raw, _ = floor_verify.load_canonical(base[84], "final observer bundle")
    entries = journal_verify.expected_entries(
        old_bundle_raw,
        first_rotation_raw,
        first_auth_raw,
        first_successor_raw,
        second_rotation_raw,
        second_auth_raw,
        final_bundle_raw,
    )

    prefix_journal_raw, prefix_journal = floor_verify.load_canonical(
        base[85], "prefix observer rotation journal"
    )
    prefix_checkpoint_raw, prefix_checkpoint = floor_verify.load_canonical(
        base[86], "prefix observer rotation checkpoint"
    )
    final_journal_raw, final_journal = floor_verify.load_canonical(
        base[87], "final observer rotation journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base[88], "final observer rotation checkpoint"
    )
    fork_raw, fork_checkpoint = floor_verify.load_canonical(
        fork_path, "fork observer rotation checkpoint"
    )

    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw,
        material_verify.canonical(entries[1]),
        1,
        journal_verify.rotation1_verify.new_observer_set(),
        None,
        2,
        target,
        source_sha,
    )
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw,
        material_verify.canonical(entries[2]),
        2,
        journal_verify.rotation2_verify.final_observer_set(),
        journal_verify.sha256(prefix_checkpoint_raw),
        3,
        target,
        source_sha,
    )

    prefix_ok = 0
    for subset in itertools.combinations(
        prefix_checkpoint["observers"], journal_verify.THRESHOLD
    ):
        candidate = copy.deepcopy(prefix_checkpoint)
        candidate["observers"] = list(subset)
        journal_verify.validate_checkpoint(
            candidate,
            prefix_journal_raw,
            prefix_statement,
            journal_verify.rotation1_verify.NEW_PINNED_OBSERVERS,
            "prefix subset",
        )
        prefix_ok += 1
    if prefix_ok != 3:
        raise AssertionError("unexpected RUST-065 prefix subset count")
    print("[GREEN] RUST-065 prefix checkpoint availability: 3/3 valid two-observer subsets accepted")

    final_ok = 0
    for subset in itertools.combinations(
        final_checkpoint["observers"], journal_verify.THRESHOLD
    ):
        candidate = copy.deepcopy(final_checkpoint)
        candidate["observers"] = list(subset)
        journal_verify.validate_checkpoint(
            candidate,
            final_journal_raw,
            final_statement,
            journal_verify.rotation2_verify.FINAL_PINNED_OBSERVERS,
            "final subset",
        )
        final_ok += 1
    if final_ok != 3:
        raise AssertionError("unexpected RUST-065 final subset count")
    print("[GREEN] RUST-065 final checkpoint availability: 3/3 valid two-observer subsets accepted")

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

        value = copy.deepcopy(prefix_journal); value["entries"][0]["observer_set_sha256"] = "0" * 64
        expect_failure("prefix-genesis-set-rewrite", lambda: run_with(85, write_obj("a.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["entries"][1]["rotation_sha256"] = "0" * 64
        expect_failure("prefix-first-rotation-digest", lambda: run_with(85, write_obj("b.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["entries"][1]["rotation_auth_sha256"] = "0" * 64
        expect_failure("prefix-first-rotation-auth-digest", lambda: run_with(85, write_obj("c.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["monitor_rotation_journal_checkpoint_sha256"] = "0" * 64
        expect_failure("prefix-monitored-checkpoint", lambda: run_with(85, write_obj("d.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["monitor_rotation_journal_checkpoint_statement_sha256"] = "0" * 64
        expect_failure("prefix-monitored-statement", lambda: run_with(85, write_obj("e.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["observed_target_sha256"] = "0" * 64
        expect_failure("prefix-observed-target", lambda: run_with(85, write_obj("f.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["activation_source_commit"] = "0" * 40
        expect_failure("prefix-source", lambda: run_with(85, write_obj("g.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["production"] = True
        expect_failure("prefix-production", lambda: run_with(85, write_obj("h.json", value))); cases += 1

        value = copy.deepcopy(final_journal); value["entries"] = value["entries"][:2]
        expect_failure("final-entry-truncation", lambda: run_with(87, write_obj("i.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][0]["observation_bundle_sha256"] = "0" * 64
        expect_failure("final-prefix-rewrite", lambda: run_with(87, write_obj("j.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["sequence"] = 1
        expect_failure("final-sequence-rollback", lambda: run_with(87, write_obj("k.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["predecessor_entry_sha256"] = "0" * 64
        expect_failure("final-predecessor-entry", lambda: run_with(87, write_obj("l.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_sha256"] = "0" * 64
        expect_failure("final-rotation-digest", lambda: run_with(87, write_obj("m.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_auth_sha256"] = "0" * 64
        expect_failure("final-rotation-auth-digest", lambda: run_with(87, write_obj("n.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["observation_bundle_sha256"] = "0" * 64
        expect_failure("final-observation-bundle", lambda: run_with(87, write_obj("o.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["cumulative_revoked_observer_ids"] = [journal_verify.rotation1_verify.REVOKED_OBSERVER_ID]
        expect_failure("final-revocation-omission", lambda: run_with(87, write_obj("p.json", value))); cases += 1

        value = copy.deepcopy(prefix_checkpoint); value["threshold"] = 1
        expect_failure("prefix-threshold", lambda: run_with(86, write_obj("q.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["observers"] = value["observers"][:1]
        expect_failure("prefix-below-threshold", lambda: run_with(86, write_obj("r.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["observers"] = [value["observers"][0], copy.deepcopy(value["observers"][0])]
        expect_failure("prefix-duplicate", lambda: run_with(86, write_obj("s.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); sig = bytearray(base64.b64decode(value["observers"][0]["signature"])); sig[0] ^= 1; value["observers"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("prefix-signature", lambda: run_with(86, write_obj("t.json", value))); cases += 1

        value = copy.deepcopy(final_checkpoint); value["statement"]["previous_checkpoint_sha256"] = "0" * 64
        expect_failure("final-previous-checkpoint", lambda: run_with(88, write_obj("u.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["head_entry_sha256"] = "0" * 64
        expect_failure("final-head-entry", lambda: run_with(88, write_obj("v.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["monitor_rotation_journal_checkpoint_sha256"] = "0" * 64
        expect_failure("final-monitored-checkpoint", lambda: run_with(88, write_obj("w.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["monitor_rotation_journal_checkpoint_statement_sha256"] = "0" * 64
        expect_failure("final-monitored-statement", lambda: run_with(88, write_obj("x.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["observed_target_sha256"] = "0" * 64
        expect_failure("final-observed-target", lambda: run_with(88, write_obj("y.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["activation_source_commit"] = "0" * 40
        expect_failure("final-source", lambda: run_with(88, write_obj("z.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["production"] = True
        expect_failure("final-production", lambda: run_with(88, write_obj("aa.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["observer_set_sequence"] = 1
        expect_failure("final-observer-set-sequence", lambda: run_with(88, write_obj("ab.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["observer_set_sha256"] = "0" * 64
        expect_failure("final-observer-set-digest", lambda: run_with(88, write_obj("ac.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["threshold"] = 1
        expect_failure("final-threshold", lambda: run_with(88, write_obj("ad.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["observers"] = value["observers"][:1]
        expect_failure("final-below-threshold", lambda: run_with(88, write_obj("ae.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); sig = bytearray(base64.b64decode(value["observers"][-1]["signature"])); sig[-1] ^= 1; value["observers"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("final-signature", lambda: run_with(88, write_obj("af.json", value))); cases += 1

        noncanonical_journal = root / "noncanonical-journal.json"
        noncanonical_journal.write_text(json.dumps(final_journal, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final-journal", lambda: run_with(87, noncanonical_journal)); cases += 1
        noncanonical_checkpoint = root / "noncanonical-checkpoint.json"
        noncanonical_checkpoint.write_text(json.dumps(final_checkpoint, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final-checkpoint", lambda: run_with(88, noncanonical_checkpoint)); cases += 1

        expect_failure(
            "observed-valid-same-parent-monitor-rotation-journal-observer-rotation-journal-fork",
            lambda: journal_verify.reject_observed_fork(
                final_checkpoint_raw,
                final_checkpoint,
                fork_raw,
                fork_checkpoint,
                final_journal_raw,
                journal_verify.rotation2_verify.FINAL_PINNED_OBSERVERS,
            ),
        ); cases += 1

    if cases != 35:
        raise AssertionError(f"unexpected RUST-065 fail-closed case count: {cases}")
    print("RUST-065 monitor-rotation-journal observer rotation journal fail-closed contract: 35/35 expected cases passed")


if __name__ == "__main__":
    main()
