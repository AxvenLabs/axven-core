#!/usr/bin/env python3
"""RUST-040 detached multi-step observer-set rotation fail-closed selftest."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_040_multistep_observer_rotation_verify as rotation_verify


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 24:
        raise SystemExit("usage: rust_040_multistep_observer_rotation_selftest.py ... SECOND_ROTATION SECOND_AUTH FINAL_BUNDLE FORK OLD_SUCCESSOR SOURCE_SHA REQUIRED_FLOOR")
    source_sha, required_floor = sys.argv[-2:]
    paths = [Path(value) for value in sys.argv[1:-2]]
    *base_through_first_successor, second_rotation_path, second_auth_path, final_bundle_path, fork_path, old_successor_replay_path = paths
    _, second_rotation = floor_verify.load_canonical(second_rotation_path, "second observer rotation")
    _, second_auth = floor_verify.load_canonical(second_auth_path, "second observer auth")
    _, final_bundle = floor_verify.load_canonical(final_bundle_path, "final observer bundle")
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        def run(rp=second_rotation_path, ap=second_auth_path, bp=final_bundle_path):
            rotation_verify.verify(*base_through_first_successor, rp, ap, bp, source_sha, required_floor)

        for idx, pair in enumerate(((0, 1), (0, 2), (1, 2)), start=1):
            value = copy.deepcopy(second_auth)
            value["observers"] = [copy.deepcopy(second_auth["observers"][i]) for i in pair]
            value["observers"].sort(key=lambda item: item["observer_id"])
            run(ap=write(f"valid-auth-{idx}.json", value))
        print("[GREEN] RUST-040 second rotation authorization availability: 3/3 valid two-observer subsets accepted")

        for idx, pair in enumerate(((0, 1), (0, 2), (1, 2)), start=1):
            value = copy.deepcopy(final_bundle)
            value["reports"] = [copy.deepcopy(final_bundle["reports"][i]) for i in pair]
            value["reports"].sort(key=lambda report: report["statement"]["observer_id"])
            run(bp=write(f"valid-final-{idx}.json", value))
        print("[GREEN] RUST-040 final observer availability: 3/3 valid two-observer subsets accepted")

        mutations = []
        value = copy.deepcopy(second_rotation); value["sequence"] = 1; mutations.append(("rotation-sequence-rollback", "r", value))
        value = copy.deepcopy(second_rotation); value["from_set_sha256"] = "0" * 64; mutations.append(("rotation-predecessor-set", "r", value))
        value = copy.deepcopy(second_rotation); value["to_set"]["threshold"] = 1; mutations.append(("final-set-threshold-downgrade", "r", value))
        value = copy.deepcopy(second_rotation); value["to_set"]["observers"][0] = {"observer_id": rotation_verify.CUMULATIVE_REVOKED_OBSERVER_IDS[1], "public_key": rotation_verify.PREDECESSOR_PINNED_OBSERVERS[rotation_verify.CUMULATIVE_REVOKED_OBSERVER_IDS[1]].hex()}; value["to_set"]["observers"].sort(key=lambda item: item["observer_id"]); mutations.append(("revoked-o2-resurrection", "r", value))
        value = copy.deepcopy(second_rotation); value["cumulative_revoked_observer_ids"] = value["cumulative_revoked_observer_ids"][:1]; mutations.append(("cumulative-revocation-truncation", "r", value))
        value = copy.deepcopy(second_rotation); value["predecessor_rotation_sha256"] = "0" * 64; mutations.append(("predecessor-rotation-digest", "r", value))
        value = copy.deepcopy(second_rotation); value["predecessor_successor_bundle_sha256"] = "0" * 64; mutations.append(("predecessor-successor-digest", "r", value))
        value = copy.deepcopy(second_rotation); value["checkpoint_statement_sha256"] = "0" * 64; mutations.append(("rotation-checkpoint-binding", "r", value))
        value = copy.deepcopy(second_rotation); value["activation_source_commit"] = "0" * 40; mutations.append(("rotation-source", "r", value))
        value = copy.deepcopy(second_rotation); value["production"] = True; mutations.append(("rotation-production", "r", value))

        value = copy.deepcopy(second_auth); value["observers"] = value["observers"][:1]; mutations.append(("auth-below-threshold", "a", value))
        value = copy.deepcopy(second_auth); value["threshold"] = 1; mutations.append(("auth-threshold-downgrade", "a", value))
        value = copy.deepcopy(second_auth); value["observers"][1] = copy.deepcopy(value["observers"][0]); mutations.append(("auth-duplicate-observer", "a", value))
        value = copy.deepcopy(second_auth); value["observers"] = list(reversed(value["observers"])); mutations.append(("auth-unsorted-observers", "a", value))
        value = copy.deepcopy(second_auth); value["observers"][0]["observer_id"] = "unknown-observer"; value["observers"].sort(key=lambda item: item["observer_id"]); mutations.append(("auth-unknown-observer", "a", value))
        value = copy.deepcopy(second_auth); sig = bytearray(material_verify.decode_signature(value["observers"][0]["signature"])); sig[0] ^= 1; value["observers"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); mutations.append(("auth-signature", "a", value))
        value = copy.deepcopy(second_auth); value["payload_sha256"] = "0" * 64; mutations.append(("auth-payload-digest", "a", value))
        value = copy.deepcopy(second_auth); value["production"] = True; mutations.append(("auth-production", "a", value))

        value = copy.deepcopy(final_bundle); value["reports"] = value["reports"][:1]; mutations.append(("final-below-threshold", "b", value))
        value = copy.deepcopy(final_bundle); value["threshold"] = 1; mutations.append(("final-threshold-downgrade", "b", value))
        value = copy.deepcopy(final_bundle); value["observer_set_sequence"] = 1; mutations.append(("final-epoch-rollback", "b", value))
        value = copy.deepcopy(final_bundle); value["observer_set_sha256"] = "0" * 64; mutations.append(("final-set-digest", "b", value))
        value = copy.deepcopy(final_bundle); value["reports"][1] = copy.deepcopy(value["reports"][0]); mutations.append(("final-duplicate-observer", "b", value))
        value = copy.deepcopy(final_bundle); value["reports"] = list(reversed(value["reports"])); mutations.append(("final-unsorted-observers", "b", value))
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["observer_id"] = rotation_verify.CUMULATIVE_REVOKED_OBSERVER_IDS[0]; mutations.append(("final-revoked-o1", "b", value))
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["observer_id"] = rotation_verify.CUMULATIVE_REVOKED_OBSERVER_IDS[1]; mutations.append(("final-revoked-o2", "b", value))
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["activation_source_commit"] = "0" * 40; mutations.append(("final-source", "b", value))
        value = copy.deepcopy(final_bundle); value["production"] = True; mutations.append(("final-production", "b", value))
        value = copy.deepcopy(final_bundle); sig = bytearray(material_verify.decode_signature(value["reports"][0]["signature"])); sig[0] ^= 1; value["reports"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); mutations.append(("final-signature", "b", value))

        for idx, (label, kind, value) in enumerate(mutations, start=1):
            if kind == "r": expect_failure(label, lambda value=value, idx=idx: run(rp=write(f"m-r-{idx}.json", value)))
            elif kind == "a": expect_failure(label, lambda value=value, idx=idx: run(ap=write(f"m-a-{idx}.json", value)))
            else: expect_failure(label, lambda value=value, idx=idx: run(bp=write(f"m-b-{idx}.json", value)))
            cases += 1

        noncanonical_rotation = root / "noncanonical-rotation.json"
        noncanonical_rotation.write_text(json.dumps(second_rotation, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-rotation", lambda: run(rp=noncanonical_rotation)); cases += 1
        noncanonical_auth = root / "noncanonical-auth.json"
        noncanonical_auth.write_text(json.dumps(second_auth, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-auth", lambda: run(ap=noncanonical_auth)); cases += 1
        noncanonical_final = root / "noncanonical-final.json"
        noncanonical_final.write_text(json.dumps(final_bundle, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final", lambda: run(bp=noncanonical_final)); cases += 1
        expect_failure("old-rust039-successor-replay", lambda: run(bp=old_successor_replay_path)); cases += 1
        expect_failure("observed-valid-final-fork", lambda: run(bp=fork_path)); cases += 1

    if cases != 34:
        raise AssertionError(f"unexpected RUST-040 selftest case count: {cases}")
    print("RUST-040 multi-step observer rotation fail-closed contract: 34/34 expected cases passed")


if __name__ == "__main__":
    main()
