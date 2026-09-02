#!/usr/bin/env python3
"""RUST-047 detached availability and fail-closed selftest."""
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
import rust_046_monitor_journal_gossip_verify as gossip_verify
import rust_047_journal_observer_set_rotation_verify as rotation_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 42:
        raise SystemExit(
            "usage: rust_047_journal_observer_set_rotation_selftest.py "
            "... OLD_BUNDLE ROTATION AUTH SUCCESSOR FORK_SUCCESSOR SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 38:
        raise AssertionError("unexpected RUST-047 selftest base path count")

    rotation_verify.verify(*base, source_sha, required_floor)
    checkpoint_raw, checkpoint = floor_verify.load_canonical(base[33], "final monitor checkpoint")
    old_bundle_raw, old_bundle = floor_verify.load_canonical(base[34], "old journal-observer bundle")
    rotation_raw, rotation = floor_verify.load_canonical(base[35], "journal-observer rotation")
    _, auth = floor_verify.load_canonical(base[36], "journal-observer rotation authorization")
    _, successor = floor_verify.load_canonical(base[37], "successor journal-observer bundle")
    target = gossip_verify.canonical_target(checkpoint_raw, checkpoint, source_sha)

    auth_ok = 0
    for subset in itertools.combinations(auth["observers"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(auth)
        candidate["observers"] = list(subset)
        rotation_verify.validate_rotation_auth(candidate, rotation_raw)
        auth_ok += 1
    if auth_ok != 3:
        raise AssertionError("unexpected predecessor authorization subset count")
    print("[GREEN] RUST-047 predecessor authorization availability: 3/3 valid two-observer subsets accepted")

    successor_ok = 0
    for subset in itertools.combinations(successor["reports"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(successor)
        candidate["reports"] = list(subset)
        rotation_verify.validate_successor_bundle(candidate, target)
        successor_ok += 1
    if successor_ok != 3:
        raise AssertionError("unexpected successor observation subset count")
    print("[GREEN] RUST-047 successor observation availability: 3/3 valid two-observer subsets accepted")

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
            rotation_verify.verify(*paths, source_sha, required_floor)

        value = copy.deepcopy(rotation); value["sequence"] = 0; fail("rotation-sequence", lambda: run_with(35, write("a.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["from_set_sha256"] = "0" * 64; fail("rotation-predecessor-set", lambda: run_with(35, write("b.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["to_set"]["threshold"] = 1; fail("rotation-successor-set", lambda: run_with(35, write("c.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["revoked_observer_ids"] = []; fail("rotation-revocation", lambda: run_with(35, write("d.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["predecessor_observation_bundle_sha256"] = "0" * 64; fail("rotation-predecessor-bundle", lambda: run_with(35, write("e.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["checkpoint_sha256"] = "0" * 64; fail("rotation-checkpoint", lambda: run_with(35, write("f.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["checkpoint_statement_sha256"] = "0" * 64; fail("rotation-checkpoint-statement", lambda: run_with(35, write("g.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["activation_source_commit"] = "0" * 40; fail("rotation-source", lambda: run_with(35, write("h.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["production"] = True; fail("rotation-production", lambda: run_with(35, write("i.json", value))); cases += 1

        value = copy.deepcopy(auth); value["threshold"] = 1; fail("auth-threshold", lambda: run_with(36, write("j.json", value))); cases += 1
        value = copy.deepcopy(auth); value["observers"] = value["observers"][:1]; fail("auth-below-threshold", lambda: run_with(36, write("k.json", value))); cases += 1
        value = copy.deepcopy(auth); value["observers"] = [value["observers"][0], copy.deepcopy(value["observers"][0])]; fail("auth-duplicate", lambda: run_with(36, write("l.json", value))); cases += 1
        value = copy.deepcopy(auth); value["payload_sha256"] = "0" * 64; fail("auth-payload", lambda: run_with(36, write("m.json", value))); cases += 1
        value = copy.deepcopy(auth); sig = bytearray(material_verify.decode_signature(value["observers"][0]["signature"])); sig[0] ^= 1; value["observers"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); fail("auth-signature", lambda: run_with(36, write("n.json", value))); cases += 1

        value = copy.deepcopy(successor); value["threshold"] = 1; fail("successor-threshold", lambda: run_with(37, write("o.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"] = value["reports"][:1]; fail("successor-below-threshold", lambda: run_with(37, write("p.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][1] = copy.deepcopy(value["reports"][0]); fail("successor-duplicate", lambda: run_with(37, write("q.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"] = list(reversed(value["reports"])); fail("successor-unsorted", lambda: run_with(37, write("r.json", value))); cases += 1
        value = copy.deepcopy(successor); value["observer_set_sequence"] = 0; fail("successor-set-sequence", lambda: run_with(37, write("s.json", value))); cases += 1
        value = copy.deepcopy(successor); value["observer_set_sha256"] = "0" * 64; fail("successor-set-digest", lambda: run_with(37, write("t.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observer_id"] = rotation_verify.REVOKED_OBSERVER_ID; fail("revoked-observer-resurrection", lambda: run_with(37, write("u.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["checkpoint_sha256"] = "0" * 64; fail("successor-checkpoint", lambda: run_with(37, write("v.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["checkpoint_statement_sha256"] = "0" * 64; fail("successor-checkpoint-statement", lambda: run_with(37, write("w.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["journal_sha256"] = "0" * 64; fail("successor-journal", lambda: run_with(37, write("x.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["previous_checkpoint_sha256"] = "0" * 64; fail("successor-parent", lambda: run_with(37, write("y.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["activation_source_commit"] = "0" * 40; fail("successor-source", lambda: run_with(37, write("z.json", value))); cases += 1
        value = copy.deepcopy(successor); sig = bytearray(material_verify.decode_signature(value["reports"][-1]["signature"])); sig[-1] ^= 1; value["reports"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); fail("successor-signature", lambda: run_with(37, write("aa.json", value))); cases += 1
        value = copy.deepcopy(successor); value["production"] = True; fail("successor-production", lambda: run_with(37, write("ab.json", value))); cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(successor, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-successor", lambda: run_with(37, noncanonical)); cases += 1
        fail("old-rust046-bundle-replay", lambda: run_with(37, base[34])); cases += 1
        fail("observed-valid-successor-same-parent-fork", lambda: run_with(37, fork_path)); cases += 1

    if cases != 31:
        raise AssertionError(f"unexpected RUST-047 selftest case count: {cases}")
    print("RUST-047 journal-observer rotation fail-closed contract: 31/31 expected cases passed")


if __name__ == "__main__":
    main()
