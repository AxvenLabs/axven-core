#!/usr/bin/env python3
"""RUST-060 detached multi-step monitor rotation availability/fail-closed selftest."""
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
import rust_058_observer_rotation_journal_monitor_verify as monitor_verify
import rust_060_multistep_observer_rotation_journal_monitor_rotation_verify as rotation_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 78:
        raise SystemExit("usage: rust_060_multistep_observer_rotation_journal_monitor_rotation_selftest.py ... FINAL_BUNDLE FORK_BUNDLE SOURCE_SHA REQUIRED_FLOOR")
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 74:
        raise AssertionError("unexpected RUST-060 selftest base path count")

    rotation_verify.verify(*base, source_sha, required_floor)
    checkpoint_raw, checkpoint = floor_verify.load_canonical(base[66], "final observer-rotation checkpoint")
    first_rotation_raw, _ = floor_verify.load_canonical(base[68], "first monitor rotation")
    first_auth_raw, _ = floor_verify.load_canonical(base[69], "first monitor auth")
    first_successor_raw, _ = floor_verify.load_canonical(base[70], "first successor monitor bundle")
    second_rotation_raw, second_rotation = floor_verify.load_canonical(base[71], "second monitor rotation")
    _, auth = floor_verify.load_canonical(base[72], "second monitor rotation authorization")
    _, final_bundle = floor_verify.load_canonical(base[73], "final monitor bundle")
    target = monitor_verify.checkpoint_target(checkpoint_raw, checkpoint["statement"])

    auth_ok = 0
    for subset in itertools.combinations(auth["monitors"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(auth); candidate["monitors"] = list(subset)
        rotation_verify.validate_rotation_auth(candidate, second_rotation_raw); auth_ok += 1
    if auth_ok != 3:
        raise AssertionError("unexpected RUST-060 authorization subset count")
    print("[GREEN] RUST-060 second-rotation authorization availability: 3/3 valid two-monitor subsets accepted")

    final_ok = 0
    for subset in itertools.combinations(final_bundle["reports"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(final_bundle); candidate["reports"] = list(subset)
        rotation_verify.validate_final_bundle(candidate, target); final_ok += 1
    if final_ok != 3:
        raise AssertionError("unexpected RUST-060 final subset count")
    print("[GREEN] RUST-060 final monitoring availability: 3/3 valid two-monitor subsets accepted")

    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        def write(name: str, value: dict) -> Path:
            path = root / name; path.write_bytes(material_verify.canonical(value)); return path
        def run_with(index: int, path: Path) -> None:
            paths = list(base); paths[index] = path; rotation_verify.verify(*paths, source_sha, required_floor)

        value = copy.deepcopy(second_rotation); value["sequence"] = 1; fail("sequence-rollback", lambda: run_with(71, write("a.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["from_set_sha256"] = "0" * 64; fail("predecessor-set", lambda: run_with(71, write("b.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["to_set"]["threshold"] = 1; fail("final-set", lambda: run_with(71, write("c.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["cumulative_revoked_monitor_ids"] = value["cumulative_revoked_monitor_ids"][:1]; fail("revocation-omission", lambda: run_with(71, write("d.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["predecessor_rotation_sha256"] = "0" * 64; fail("predecessor-rotation", lambda: run_with(71, write("e.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["predecessor_rotation_auth_sha256"] = "0" * 64; fail("predecessor-auth", lambda: run_with(71, write("f.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["predecessor_successor_bundle_sha256"] = "0" * 64; fail("predecessor-bundle", lambda: run_with(71, write("g.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["observer_rotation_journal_checkpoint_sha256"] = "0" * 64; fail("checkpoint", lambda: run_with(71, write("h.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["observer_rotation_journal_checkpoint_statement_sha256"] = "0" * 64; fail("checkpoint-statement", lambda: run_with(71, write("i.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["observed_checkpoint_sha256"] = "0" * 64; fail("inherited-observed-checkpoint", lambda: run_with(71, write("j.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["activation_source_commit"] = "0" * 40; fail("source", lambda: run_with(71, write("k.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["production"] = True; fail("rotation-production", lambda: run_with(71, write("l.json", value))); cases += 1

        value = copy.deepcopy(auth); value["threshold"] = 1; fail("auth-threshold", lambda: run_with(72, write("m.json", value))); cases += 1
        value = copy.deepcopy(auth); value["monitors"] = value["monitors"][:1]; fail("auth-below-threshold", lambda: run_with(72, write("n.json", value))); cases += 1
        value = copy.deepcopy(auth); value["payload_sha256"] = "0" * 64; fail("auth-payload", lambda: run_with(72, write("o.json", value))); cases += 1
        value = copy.deepcopy(auth); value["monitors"] = [value["monitors"][0], copy.deepcopy(value["monitors"][0])]; fail("auth-duplicate", lambda: run_with(72, write("p.json", value))); cases += 1
        value = copy.deepcopy(auth); sig = bytearray(material_verify.decode_signature(value["monitors"][0]["signature"])); sig[0] ^= 1; value["monitors"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); fail("auth-signature", lambda: run_with(72, write("q.json", value))); cases += 1

        value = copy.deepcopy(final_bundle); value["threshold"] = 1; fail("final-threshold", lambda: run_with(73, write("r.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"] = value["reports"][:1]; fail("final-below-threshold", lambda: run_with(73, write("s.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][1] = copy.deepcopy(value["reports"][0]); fail("final-duplicate", lambda: run_with(73, write("t.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"] = list(reversed(value["reports"])); fail("final-unsorted", lambda: run_with(73, write("u.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["monitor_set_sequence"] = 1; fail("final-set-sequence", lambda: run_with(73, write("v.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["monitor_set_sha256"] = "0" * 64; fail("final-set-digest", lambda: run_with(73, write("w.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["monitor_id"] = rotation_verify.CUMULATIVE_REVOKED_MONITOR_IDS[-1]; fail("revoked-monitor-resurrection", lambda: run_with(73, write("x.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["observer_rotation_journal_checkpoint_sha256"] = "0" * 64; fail("final-checkpoint", lambda: run_with(73, write("y.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["observer_rotation_journal_checkpoint_statement_sha256"] = "0" * 64; fail("final-checkpoint-statement", lambda: run_with(73, write("z.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["observed_checkpoint_sha256"] = "0" * 64; fail("final-observed-checkpoint", lambda: run_with(73, write("aa.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["journal_sha256"] = "0" * 64; fail("final-journal", lambda: run_with(73, write("ab.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["previous_checkpoint_sha256"] = "0" * 64; fail("final-parent", lambda: run_with(73, write("ac.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["activation_source_commit"] = "0" * 40; fail("final-source", lambda: run_with(73, write("ad.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); sig = bytearray(material_verify.decode_signature(value["reports"][-1]["signature"])); sig[-1] ^= 1; value["reports"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); fail("final-signature", lambda: run_with(73, write("ae.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["production"] = True; fail("final-production", lambda: run_with(73, write("af.json", value))); cases += 1

        noncanonical = root / "noncanonical.json"; noncanonical.write_text(json.dumps(final_bundle, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-final", lambda: run_with(73, noncanonical)); cases += 1
        fail("rust059-v2-bundle-replay", lambda: run_with(73, base[70])); cases += 1
        fail("observed-valid-final-same-parent-fork", lambda: run_with(73, fork_path)); cases += 1

    if cases != 35:
        raise AssertionError(f"unexpected RUST-060 selftest case count: {cases}")
    print("RUST-060 multi-step observer-rotation-journal monitor rotation fail-closed contract: 35/35 expected cases passed")


if __name__ == "__main__":
    main()
