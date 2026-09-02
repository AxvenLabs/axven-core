#!/usr/bin/env python3
"""RUST-039 detached observer-set rotation fail-closed selftest."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_039_observer_set_rotation_verify as rotation_verify


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 21:
        raise SystemExit("usage: rust_039_observer_set_rotation_selftest.py ... ROTATION AUTH SUCCESSOR FORK OLD_BUNDLE SOURCE_SHA REQUIRED_FLOOR")
    source_sha, required_floor = sys.argv[-2:]
    paths = [Path(value) for value in sys.argv[1:-2]]
    *base_through_old_bundle, rotation_path, auth_path, successor_path, fork_path, old_bundle_replay_path = paths
    rotation_raw, rotation = floor_verify.load_canonical(rotation_path, "observer-set rotation")
    _, auth = floor_verify.load_canonical(auth_path, "rotation auth")
    _, successor = floor_verify.load_canonical(successor_path, "successor bundle")
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        def run(rp=rotation_path, ap=auth_path, sp=successor_path):
            rotation_verify.verify(*base_through_old_bundle, rp, ap, sp, source_sha, required_floor)

        # Any valid 2-of-3 predecessor observer authorizers must authorize the exact rotation.
        for idx, pair in enumerate(((0, 1), (0, 2), (1, 2)), start=1):
            value = copy.deepcopy(auth)
            value["observers"] = [copy.deepcopy(auth["observers"][i]) for i in pair]
            value["observers"].sort(key=lambda item: item["observer_id"])
            run(ap=write(f"valid-auth-{idx}.json", value))
        print("[GREEN] RUST-039 rotation authorization availability: 3/3 valid two-observer subsets accepted")

        # Any valid 2-of-3 successor observers must satisfy the new observer-set quorum.
        for idx, pair in enumerate(((0, 1), (0, 2), (1, 2)), start=1):
            value = copy.deepcopy(successor)
            value["reports"] = [copy.deepcopy(successor["reports"][i]) for i in pair]
            value["reports"].sort(key=lambda report: report["statement"]["observer_id"])
            run(sp=write(f"valid-successor-{idx}.json", value))
        print("[GREEN] RUST-039 successor observer availability: 3/3 valid two-observer subsets accepted")

        mutations = []
        value = copy.deepcopy(rotation); value["sequence"] = 0; mutations.append(("rotation-sequence-rollback", "r", value))
        value = copy.deepcopy(rotation); value["from_set_sha256"] = "0" * 64; mutations.append(("rotation-predecessor-set", "r", value))
        value = copy.deepcopy(rotation); value["to_set"]["threshold"] = 1; mutations.append(("successor-set-threshold-downgrade", "r", value))
        value = copy.deepcopy(rotation); value["to_set"]["observers"][0] = {"observer_id": rotation_verify.REVOKED_OBSERVER_ID, "public_key": rotation_verify.OLD_PINNED_OBSERVERS[rotation_verify.REVOKED_OBSERVER_ID].hex()}; value["to_set"]["observers"].sort(key=lambda item: item["observer_id"]); mutations.append(("revoked-o1-resurrection", "r", value))
        value = copy.deepcopy(rotation); value["revoked_observer_ids"] = []; mutations.append(("revocation-omission", "r", value))
        value = copy.deepcopy(rotation); value["checkpoint_statement_sha256"] = "0" * 64; mutations.append(("rotation-checkpoint-binding", "r", value))
        value = copy.deepcopy(rotation); value["activation_source_commit"] = "0" * 40; mutations.append(("rotation-source", "r", value))
        value = copy.deepcopy(rotation); value["production"] = True; mutations.append(("rotation-production", "r", value))

        value = copy.deepcopy(auth); value["observers"] = value["observers"][:1]; mutations.append(("auth-below-threshold", "a", value))
        value = copy.deepcopy(auth); value["threshold"] = 1; mutations.append(("auth-threshold-downgrade", "a", value))
        value = copy.deepcopy(auth); value["observers"][1] = copy.deepcopy(value["observers"][0]); mutations.append(("auth-duplicate-observer", "a", value))
        value = copy.deepcopy(auth); value["observers"] = list(reversed(value["observers"])); mutations.append(("auth-unsorted-observers", "a", value))
        value = copy.deepcopy(auth); value["observers"][0]["observer_id"] = "unknown-observer"; value["observers"].sort(key=lambda item: item["observer_id"]); mutations.append(("auth-unknown-observer", "a", value))
        value = copy.deepcopy(auth); sig = bytearray(material_verify.decode_signature(value["observers"][0]["signature"])); sig[0] ^= 1; value["observers"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); mutations.append(("auth-signature", "a", value))
        value = copy.deepcopy(auth); value["payload_sha256"] = "0" * 64; mutations.append(("auth-payload-digest", "a", value))
        value = copy.deepcopy(auth); value["production"] = True; mutations.append(("auth-production", "a", value))

        value = copy.deepcopy(successor); value["reports"] = value["reports"][:1]; mutations.append(("successor-below-threshold", "s", value))
        value = copy.deepcopy(successor); value["threshold"] = 1; mutations.append(("successor-threshold-downgrade", "s", value))
        value = copy.deepcopy(successor); value["observer_set_sequence"] = 0; mutations.append(("successor-epoch-rollback", "s", value))
        value = copy.deepcopy(successor); value["observer_set_sha256"] = "0" * 64; mutations.append(("successor-set-digest", "s", value))
        value = copy.deepcopy(successor); value["reports"][1] = copy.deepcopy(value["reports"][0]); mutations.append(("successor-duplicate-observer", "s", value))
        value = copy.deepcopy(successor); value["reports"] = list(reversed(value["reports"])); mutations.append(("successor-unsorted-observers", "s", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observer_id"] = rotation_verify.REVOKED_OBSERVER_ID; mutations.append(("successor-revoked-o1", "s", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["activation_source_commit"] = "0" * 40; mutations.append(("successor-source", "s", value))
        value = copy.deepcopy(successor); value["production"] = True; mutations.append(("successor-production", "s", value))
        value = copy.deepcopy(successor); sig = bytearray(material_verify.decode_signature(value["reports"][0]["signature"])); sig[0] ^= 1; value["reports"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); mutations.append(("successor-signature", "s", value))

        for idx, (label, kind, value) in enumerate(mutations, start=1):
            if kind == "r": expect_failure(label, lambda value=value, idx=idx: run(rp=write(f"m-r-{idx}.json", value)))
            elif kind == "a": expect_failure(label, lambda value=value, idx=idx: run(ap=write(f"m-a-{idx}.json", value)))
            else: expect_failure(label, lambda value=value, idx=idx: run(sp=write(f"m-s-{idx}.json", value)))
            cases += 1

        noncanonical_rotation = root / "noncanonical-rotation.json"
        noncanonical_rotation.write_text(json.dumps(rotation, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-rotation", lambda: run(rp=noncanonical_rotation)); cases += 1
        noncanonical_auth = root / "noncanonical-auth.json"
        noncanonical_auth.write_text(json.dumps(auth, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-auth", lambda: run(ap=noncanonical_auth)); cases += 1
        noncanonical_successor = root / "noncanonical-successor.json"
        noncanonical_successor.write_text(json.dumps(successor, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-successor", lambda: run(sp=noncanonical_successor)); cases += 1
        expect_failure("old-rust038-bundle-replay", lambda: run(sp=old_bundle_replay_path)); cases += 1
        expect_failure("observed-valid-successor-fork", lambda: run(sp=fork_path)); cases += 1

    if cases != 31:
        raise AssertionError(f"unexpected RUST-039 selftest case count: {cases}")
    print("RUST-039 observer-set rotation fail-closed contract: 31/31 expected cases passed")


if __name__ == "__main__":
    main()
