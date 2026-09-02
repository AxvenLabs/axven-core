#!/usr/bin/env python3
"""RUST-041 availability and fail-closed selftest for observer rotation journal continuity."""
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
import rust_038_checkpoint_gossip_verify as gossip_verify
import rust_039_observer_set_rotation_verify as rotation1_verify
import rust_040_multistep_observer_rotation_verify as rotation2_verify
import rust_041_observer_rotation_journal_verify as journal_verify


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 27:
        raise SystemExit("usage: rust_041_observer_rotation_journal_selftest.py ... FORK_OBSERVER_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR")
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha = sys.argv[-2]
    required_floor = sys.argv[-1]
    if len(base) != 23:
        raise AssertionError("unexpected RUST-041 base path count")

    journal_verify.verify(*base, source_sha, required_floor)

    old_bundle_raw, _ = floor_verify.load_canonical(base[12], "old observer bundle")
    first_rotation_raw, _ = floor_verify.load_canonical(base[13], "first observer rotation")
    first_auth_raw, _ = floor_verify.load_canonical(base[14], "first observer auth")
    first_successor_raw, _ = floor_verify.load_canonical(base[15], "first observer successor")
    second_rotation_raw, _ = floor_verify.load_canonical(base[16], "second observer rotation")
    second_auth_raw, _ = floor_verify.load_canonical(base[17], "second observer auth")
    final_bundle_raw, _ = floor_verify.load_canonical(base[18], "final observer bundle")
    _, witness_checkpoint = floor_verify.load_canonical(base[11], "final witness checkpoint")
    target = gossip_verify.canonical_target(witness_checkpoint, source_sha)
    target_digest = target["checkpoint_statement_sha256"]
    entries = journal_verify.expected_entries(
        old_bundle_raw, first_rotation_raw, first_auth_raw, first_successor_raw,
        second_rotation_raw, second_auth_raw, final_bundle_raw,
    )
    prefix_journal_raw, prefix_journal = floor_verify.load_canonical(base[19], "prefix observer journal")
    prefix_checkpoint_raw, prefix_checkpoint = floor_verify.load_canonical(base[20], "prefix observer checkpoint")
    final_journal_raw, final_journal = floor_verify.load_canonical(base[21], "final observer journal")
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(base[22], "final observer checkpoint")
    fork_raw, fork_checkpoint = floor_verify.load_canonical(fork_path, "fork observer checkpoint")
    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw, material_verify.canonical(entries[1]), 1, rotation1_verify.new_observer_set(),
        None, 2, target_digest, source_sha,
    )
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw, material_verify.canonical(entries[2]), 2, rotation2_verify.final_observer_set(),
        journal_verify.sha256(prefix_checkpoint_raw), 3, target_digest, source_sha,
    )

    prefix_ok = 0
    for subset in itertools.combinations(prefix_checkpoint["observers"], journal_verify.THRESHOLD):
        candidate = copy.deepcopy(prefix_checkpoint)
        candidate["observers"] = list(subset)
        journal_verify.validate_checkpoint(candidate, prefix_journal_raw, prefix_statement, rotation1_verify.NEW_PINNED_OBSERVERS, "prefix subset")
        prefix_ok += 1
    if prefix_ok != 3:
        raise AssertionError("unexpected prefix observer availability subset count")
    print("[GREEN] RUST-041 prefix observer checkpoint availability: 3/3 valid two-observer subsets accepted")

    final_ok = 0
    for subset in itertools.combinations(final_checkpoint["observers"], journal_verify.THRESHOLD):
        candidate = copy.deepcopy(final_checkpoint)
        candidate["observers"] = list(subset)
        journal_verify.validate_checkpoint(candidate, final_journal_raw, final_statement, rotation2_verify.FINAL_PINNED_OBSERVERS, "final subset")
        final_ok += 1
    if final_ok != 3:
        raise AssertionError("unexpected final observer availability subset count")
    print("[GREEN] RUST-041 final observer checkpoint availability: 3/3 valid two-observer subsets accepted")

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
        expect_failure("prefix-genesis-set-rewrite", lambda: run_with(19, write_obj("a.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["activation_source_commit"] = "0" * 40
        expect_failure("prefix-source", lambda: run_with(19, write_obj("b.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["checkpoint_statement_sha256"] = "0" * 64
        expect_failure("prefix-checkpoint-binding", lambda: run_with(19, write_obj("c.json", value))); cases += 1
        value = copy.deepcopy(prefix_journal); value["production"] = True
        expect_failure("prefix-production", lambda: run_with(19, write_obj("d.json", value))); cases += 1

        value = copy.deepcopy(final_journal); value["entries"] = value["entries"][:2]
        expect_failure("final-entry-truncation", lambda: run_with(21, write_obj("e.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][0]["observation_bundle_sha256"] = "0" * 64
        expect_failure("final-prefix-rewrite", lambda: run_with(21, write_obj("f.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["sequence"] = 1
        expect_failure("final-sequence-rollback", lambda: run_with(21, write_obj("g.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["predecessor_entry_sha256"] = "0" * 64
        expect_failure("final-predecessor-entry", lambda: run_with(21, write_obj("h.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_sha256"] = "0" * 64
        expect_failure("final-rotation-digest", lambda: run_with(21, write_obj("i.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["rotation_auth_sha256"] = "0" * 64
        expect_failure("final-rotation-auth-digest", lambda: run_with(21, write_obj("j.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["observation_bundle_sha256"] = "0" * 64
        expect_failure("final-observation-digest", lambda: run_with(21, write_obj("k.json", value))); cases += 1
        value = copy.deepcopy(final_journal); value["entries"][2]["cumulative_revoked_observer_ids"] = [rotation1_verify.REVOKED_OBSERVER_ID]
        expect_failure("final-revocation-omission", lambda: run_with(21, write_obj("l.json", value))); cases += 1

        value = copy.deepcopy(prefix_checkpoint); value["threshold"] = 1
        expect_failure("prefix-threshold-downgrade", lambda: run_with(20, write_obj("m.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["observers"] = value["observers"][:1]
        expect_failure("prefix-below-threshold", lambda: run_with(20, write_obj("n.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); value["observers"] = [value["observers"][0], value["observers"][0]]
        expect_failure("prefix-duplicate-observer", lambda: run_with(20, write_obj("o.json", value))); cases += 1
        value = copy.deepcopy(prefix_checkpoint); sig = bytearray(base64.b64decode(value["observers"][0]["signature"])); sig[0] ^= 1; value["observers"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("prefix-signature", lambda: run_with(20, write_obj("p.json", value))); cases += 1

        value = copy.deepcopy(final_checkpoint); value["statement"]["previous_checkpoint_sha256"] = "0" * 64
        expect_failure("final-previous-checkpoint", lambda: run_with(22, write_obj("q.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["head_entry_sha256"] = "0" * 64
        expect_failure("final-head-entry", lambda: run_with(22, write_obj("r.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["checkpoint_statement_sha256"] = "0" * 64
        expect_failure("final-checkpoint-binding", lambda: run_with(22, write_obj("s.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["activation_source_commit"] = "0" * 40
        expect_failure("final-source", lambda: run_with(22, write_obj("t.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["statement"]["production"] = True
        expect_failure("final-production", lambda: run_with(22, write_obj("u.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["threshold"] = 1
        expect_failure("final-threshold-downgrade", lambda: run_with(22, write_obj("v.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); value["observers"] = value["observers"][:1]
        expect_failure("final-below-threshold", lambda: run_with(22, write_obj("w.json", value))); cases += 1
        value = copy.deepcopy(final_checkpoint); sig = bytearray(base64.b64decode(value["observers"][-1]["signature"])); sig[-1] ^= 1; value["observers"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("final-signature", lambda: run_with(22, write_obj("x.json", value))); cases += 1

        noncanonical_journal = root / "noncanonical-journal.json"
        noncanonical_journal.write_text(json.dumps(final_journal, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final-journal", lambda: run_with(21, noncanonical_journal)); cases += 1
        noncanonical_checkpoint = root / "noncanonical-checkpoint.json"
        noncanonical_checkpoint.write_text(json.dumps(final_checkpoint, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final-checkpoint", lambda: run_with(22, noncanonical_checkpoint)); cases += 1

        expect_failure(
            "observed-valid-same-parent-observer-journal-fork",
            lambda: journal_verify.reject_observed_fork(
                final_checkpoint_raw, final_checkpoint, fork_raw, fork_checkpoint,
                final_journal_raw, rotation2_verify.FINAL_PINNED_OBSERVERS,
            ),
        ); cases += 1

    if cases != 27:
        raise AssertionError(f"unexpected RUST-041 fail-closed case count: {cases}")
    print("RUST-041 observer rotation journal fail-closed contract: 27/27 expected cases passed")


if __name__ == "__main__":
    main()
