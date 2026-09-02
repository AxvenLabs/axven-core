#!/usr/bin/env python3
"""RUST-038 detached fail-closed selftest."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_038_checkpoint_gossip_verify as gossip_verify


def fail(label, fn):
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 17:
        raise SystemExit("usage: rust_038_checkpoint_gossip_selftest.py ... BUNDLE FORK_BUNDLE SOURCE_SHA REQUIRED_FLOOR")
    paths = [Path(value) for value in sys.argv[1:-2]]
    *base_paths, bundle_path, fork_bundle_path = paths
    source_sha, required_floor = sys.argv[-2:]
    final_checkpoint_path = base_paths[-1]
    _, checkpoint = floor_verify.load_canonical(final_checkpoint_path, "final checkpoint")
    _, bundle = floor_verify.load_canonical(bundle_path, "observer bundle")
    target = gossip_verify.canonical_target(checkpoint, source_sha)
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        def write(name, value):
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path
        def run(path):
            gossip_verify.verify(*base_paths, path, source_sha, required_floor)

        # Availability: every valid 2-of-3 observer subset must be accepted.
        for idx, pair in enumerate(((0, 1), (0, 2), (1, 2)), start=1):
            value = copy.deepcopy(bundle)
            value["reports"] = [copy.deepcopy(bundle["reports"][i]) for i in pair]
            value["reports"].sort(key=lambda report: report["statement"]["observer_id"])
            run(write(f"valid-{idx}.json", value))
        print("[GREEN] RUST-038 observer availability: 3/3 valid two-observer subsets accepted")

        mutations = []
        value = copy.deepcopy(bundle); value["reports"] = value["reports"][:1]; mutations.append(("below-threshold", value))
        value = copy.deepcopy(bundle); value["threshold"] = 1; mutations.append(("threshold-downgrade", value))
        value = copy.deepcopy(bundle); value["reports"][1] = copy.deepcopy(value["reports"][0]); mutations.append(("duplicate-observer", value))
        value = copy.deepcopy(bundle); value["reports"] = list(reversed(value["reports"])); mutations.append(("unsorted-observers", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["observer_id"] = "unknown-observer"; mutations.append(("unknown-observer", value))
        value = copy.deepcopy(bundle); sig = bytearray(material_verify.decode_signature(value["reports"][0]["signature"])); sig[0] ^= 1; value["reports"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii"); mutations.append(("signature-mutation", value))
        value = copy.deepcopy(bundle); value["production"] = True; mutations.append(("bundle-production", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["production"] = True; mutations.append(("statement-production", value))
        value = copy.deepcopy(bundle); value["reports"][0]["algorithm"] = "none"; mutations.append(("algorithm", value))
        value = copy.deepcopy(bundle); value["schema"] = "axven-native-rotation-checkpoint-observation-bundle-v0"; mutations.append(("bundle-schema", value))
        value = copy.deepcopy(bundle); value["reports"][0]["schema"] = "axven-native-rotation-checkpoint-observation-v0"; mutations.append(("report-schema", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["activation_source_commit"] = "0" * 40; mutations.append(("source", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["set_sequence"] = 1; mutations.append(("sequence-rollback", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["previous_checkpoint_sha256"] = "0" * 64; mutations.append(("parent-substitution", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["journal_sha256"] = "0" * 64; mutations.append(("journal-digest", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["head_entry_sha256"] = "0" * 64; mutations.append(("head-digest", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["set_sha256"] = "0" * 64; mutations.append(("set-digest", value))
        value = copy.deepcopy(bundle); value["reports"][0]["statement"]["checkpoint_statement_sha256"] = "0" * 64; mutations.append(("checkpoint-statement-digest", value))

        for idx, (label, value) in enumerate(mutations, start=1):
            fail(label, lambda value=value, idx=idx: run(write(f"m-{idx}.json", value)))
            cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-bundle", lambda: run(noncanonical)); cases += 1
        fail("observed-cross-observer-fork", lambda: run(fork_bundle_path)); cases += 1

    if cases != 20:
        raise AssertionError(f"unexpected RUST-038 selftest case count: {cases}")
    print("RUST-038 checkpoint gossip fail-closed contract: 20/20 expected cases passed")


if __name__ == "__main__":
    main()
