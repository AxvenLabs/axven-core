#!/usr/bin/env python3
"""RUST-071 detached observer-set rotation availability/fail-closed selftest."""
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
import rust_070_monitor_rotation_journal_observer_verify as observer_verify
import rust_071_monitor_rotation_journal_observer_set_rotation_verify as rotation_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def changed(value):
    if type(value) is int:
        return 0 if value != 0 else 1
    if isinstance(value, str):
        return "0" * len(value)
    raise AssertionError(f"unsupported mutation value: {value!r}")


def main() -> None:
    if len(sys.argv) != 108:
        raise SystemExit(
            "usage: rust_071_monitor_rotation_journal_observer_set_rotation_selftest.py "
            "... OBSERVER_BUNDLE ROTATION AUTH SUCCESSOR FORK_SUCCESSOR SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 104:
        raise AssertionError("unexpected RUST-071 selftest path count")

    rotation_verify.verify(*base, source_sha, required_floor)
    base_paths = base[:100]
    old_bundle_path, rotation_path, auth_path, successor_path = base[100:104]
    final_checkpoint_raw, checkpoint = floor_verify.load_canonical(
        base_paths[-1], "RUST-069 final monitor rotation checkpoint"
    )
    target = observer_verify.canonical_target(final_checkpoint_raw, checkpoint, source_sha)
    _, old_bundle = floor_verify.load_canonical(old_bundle_path, "RUST-070 predecessor observer bundle")
    rotation_raw, rotation = floor_verify.load_canonical(rotation_path, "RUST-071 observer rotation")
    _, auth = floor_verify.load_canonical(auth_path, "RUST-071 observer rotation authorization")
    _, successor = floor_verify.load_canonical(successor_path, "RUST-071 successor observer bundle")

    auth_ok = 0
    for subset in itertools.combinations(auth["observers"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(auth)
        candidate["observers"] = list(subset)
        rotation_verify.validate_rotation_auth(candidate, rotation_raw)
        auth_ok += 1
    if auth_ok != 3:
        raise AssertionError("unexpected RUST-071 predecessor authorization subset count")
    print("[GREEN] RUST-071 predecessor observer authorization availability: 3/3 valid two-observer subsets accepted")

    successor_ok = 0
    for subset in itertools.combinations(successor["reports"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(successor)
        candidate["reports"] = list(subset)
        rotation_verify.validate_successor_bundle(candidate, target)
        successor_ok += 1
    if successor_ok != 3:
        raise AssertionError("unexpected RUST-071 successor observation subset count")
    print("[GREEN] RUST-071 successor observer availability: 3/3 valid two-observer subsets accepted")

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

        value = copy.deepcopy(rotation); value["sequence"] = 0; fail("rotation-sequence", lambda: run_with(101, write("r01.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["from_set_sha256"] = "0" * 64; fail("rotation-predecessor-set", lambda: run_with(101, write("r02.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["to_set"]["threshold"] = 1; fail("rotation-successor-set", lambda: run_with(101, write("r03.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["revoked_observer_ids"] = []; fail("rotation-revocation", lambda: run_with(101, write("r04.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["predecessor_observation_bundle_sha256"] = "0" * 64; fail("rotation-predecessor-bundle", lambda: run_with(101, write("r05.json", value))); cases += 1
        for idx, key in enumerate(sorted(observer_verify.TARGET_KEYS), start=6):
            value = copy.deepcopy(rotation); value[key] = changed(value[key])
            fail(f"rotation-target-{key}", lambda value=value, idx=idx: run_with(101, write(f"r{idx:02d}.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["production"] = True; fail("rotation-production", lambda: run_with(101, write("r18.json", value))); cases += 1

        value = copy.deepcopy(auth); value["threshold"] = 1; fail("auth-threshold", lambda: run_with(102, write("a19.json", value))); cases += 1
        value = copy.deepcopy(auth); value["observers"] = value["observers"][:1]; fail("auth-below-threshold", lambda: run_with(102, write("a20.json", value))); cases += 1
        value = copy.deepcopy(auth); value["observers"] = [value["observers"][0], copy.deepcopy(value["observers"][0])]; fail("auth-duplicate", lambda: run_with(102, write("a21.json", value))); cases += 1
        value = copy.deepcopy(auth); value["observers"][0]["observer_id"] = "unknown-observer"; fail("auth-unknown", lambda: run_with(102, write("a22.json", value))); cases += 1
        value = copy.deepcopy(auth); value["payload_sha256"] = "0" * 64; fail("auth-payload", lambda: run_with(102, write("a23.json", value))); cases += 1
        value = copy.deepcopy(auth); sig = bytearray(material_verify.decode_signature(value["observers"][0]["signature"])); sig[0] ^= 1; value["observers"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); fail("auth-signature", lambda: run_with(102, write("a24.json", value))); cases += 1

        value = copy.deepcopy(successor); value["threshold"] = 1; fail("successor-threshold", lambda: run_with(103, write("s25.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"] = value["reports"][:1]; fail("successor-below-threshold", lambda: run_with(103, write("s26.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][1] = copy.deepcopy(value["reports"][0]); fail("successor-duplicate", lambda: run_with(103, write("s27.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"] = list(reversed(value["reports"])); fail("successor-unsorted", lambda: run_with(103, write("s28.json", value))); cases += 1
        value = copy.deepcopy(successor); value["observer_set_sequence"] = 0; fail("successor-set-sequence", lambda: run_with(103, write("s29.json", value))); cases += 1
        value = copy.deepcopy(successor); value["observer_set_sha256"] = "0" * 64; fail("successor-set-digest", lambda: run_with(103, write("s30.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observer_id"] = rotation_verify.REVOKED_OBSERVER_ID; fail("revoked-observer-resurrection", lambda: run_with(103, write("s31.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observer_id"] = "unknown-observer"; fail("successor-unknown-observer", lambda: run_with(103, write("s32.json", value))); cases += 1
        for idx, key in enumerate(sorted(observer_verify.TARGET_KEYS), start=33):
            value = copy.deepcopy(successor); value["reports"][0]["statement"][key] = changed(value["reports"][0]["statement"][key])
            fail(f"successor-target-{key}", lambda value=value, idx=idx: run_with(103, write(f"s{idx:02d}.json", value))); cases += 1
        value = copy.deepcopy(successor); sig = bytearray(material_verify.decode_signature(value["reports"][-1]["signature"])); sig[-1] ^= 1; value["reports"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); fail("successor-signature", lambda: run_with(103, write("s45.json", value))); cases += 1
        value = copy.deepcopy(successor); value["production"] = True; fail("successor-production", lambda: run_with(103, write("s46.json", value))); cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(successor, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-successor", lambda: run_with(103, noncanonical)); cases += 1
        fail("old-rust070-bundle-replay", lambda: run_with(103, old_bundle_path)); cases += 1
        fail("observed-valid-successor-same-parent-fork", lambda: run_with(103, fork_path)); cases += 1

    if cases != 49:
        raise AssertionError(f"unexpected RUST-071 selftest case count: {cases}")
    print("RUST-071 monitor-rotation-journal observer rotation fail-closed contract: 49/49 expected cases passed")


if __name__ == "__main__":
    main()
