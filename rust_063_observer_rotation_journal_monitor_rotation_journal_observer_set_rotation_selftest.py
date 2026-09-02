#!/usr/bin/env python3
"""RUST-063 detached observer-set rotation availability/fail-closed selftest."""
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
import rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify as gossip_verify
import rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 86:
        raise SystemExit(
            "usage: rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_selftest.py "
            "... OLD_BUNDLE ROTATION AUTH SUCCESSOR FORK_SUCCESSOR SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 82:
        raise AssertionError("unexpected RUST-063 selftest base path count")

    rotation_verify.verify(*base, source_sha, required_floor)
    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        base[77], "final observer-rotation-journal monitor rotation checkpoint"
    )
    rotation_raw, rotation = floor_verify.load_canonical(
        base[79], "monitor-rotation-journal observer rotation"
    )
    _, auth = floor_verify.load_canonical(
        base[80], "monitor-rotation-journal observer rotation authorization"
    )
    _, successor = floor_verify.load_canonical(
        base[81], "successor monitor-rotation-journal observer bundle"
    )
    target = gossip_verify.canonical_target(
        checkpoint_raw, checkpoint, source_sha
    )

    auth_ok = 0
    for subset in itertools.combinations(
        auth["observers"], rotation_verify.THRESHOLD
    ):
        candidate = copy.deepcopy(auth)
        candidate["observers"] = list(subset)
        rotation_verify.validate_rotation_auth(candidate, rotation_raw)
        auth_ok += 1
    if auth_ok != 3:
        raise AssertionError("unexpected predecessor authorization subset count")
    print(
        "[GREEN] RUST-063 predecessor authorization availability: "
        "3/3 valid two-observer subsets accepted"
    )

    successor_ok = 0
    for subset in itertools.combinations(
        successor["reports"], rotation_verify.THRESHOLD
    ):
        candidate = copy.deepcopy(successor)
        candidate["reports"] = list(subset)
        rotation_verify.validate_successor_bundle(candidate, target)
        successor_ok += 1
    if successor_ok != 3:
        raise AssertionError("unexpected successor observation subset count")
    print(
        "[GREEN] RUST-063 successor observation availability: "
        "3/3 valid two-observer subsets accepted"
    )

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

        rotation_mutations = []
        value = copy.deepcopy(rotation); value["sequence"] = 0; rotation_mutations.append(("rotation-sequence", value))
        value = copy.deepcopy(rotation); value["from_set_sha256"] = "0" * 64; rotation_mutations.append(("rotation-predecessor-set", value))
        value = copy.deepcopy(rotation); value["to_set"]["threshold"] = 1; rotation_mutations.append(("rotation-successor-set", value))
        value = copy.deepcopy(rotation); value["revoked_observer_ids"] = []; rotation_mutations.append(("rotation-revocation", value))
        value = copy.deepcopy(rotation); value["predecessor_observation_bundle_sha256"] = "0" * 64; rotation_mutations.append(("rotation-predecessor-bundle", value))
        value = copy.deepcopy(rotation); value["checkpoint_sha256"] = "0" * 64; rotation_mutations.append(("rotation-checkpoint", value))
        value = copy.deepcopy(rotation); value["checkpoint_statement_sha256"] = "0" * 64; rotation_mutations.append(("rotation-checkpoint-statement", value))
        value = copy.deepcopy(rotation); value["activation_source_commit"] = "0" * 40; rotation_mutations.append(("rotation-source", value))
        value = copy.deepcopy(rotation); value["production"] = True; rotation_mutations.append(("rotation-production", value))
        for idx, (label, value) in enumerate(rotation_mutations, start=1):
            fail(label, lambda value=value, idx=idx: run_with(79, write(f"r-{idx}.json", value))); cases += 1

        auth_mutations = []
        value = copy.deepcopy(auth); value["threshold"] = 1; auth_mutations.append(("auth-threshold", value))
        value = copy.deepcopy(auth); value["observers"] = value["observers"][:1]; auth_mutations.append(("auth-below-threshold", value))
        value = copy.deepcopy(auth); value["observers"] = [value["observers"][0], copy.deepcopy(value["observers"][0])]; auth_mutations.append(("auth-duplicate", value))
        value = copy.deepcopy(auth); value["payload_sha256"] = "0" * 64; auth_mutations.append(("auth-payload", value))
        value = copy.deepcopy(auth)
        sig = bytearray(material_verify.decode_signature(value["observers"][0]["signature"]))
        sig[0] ^= 1
        value["observers"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        auth_mutations.append(("auth-signature", value))
        for idx, (label, value) in enumerate(auth_mutations, start=1):
            fail(label, lambda value=value, idx=idx: run_with(80, write(f"a-{idx}.json", value))); cases += 1

        successor_mutations = []
        value = copy.deepcopy(successor); value["threshold"] = 1; successor_mutations.append(("successor-threshold", value))
        value = copy.deepcopy(successor); value["reports"] = value["reports"][:1]; successor_mutations.append(("successor-below-threshold", value))
        value = copy.deepcopy(successor); value["reports"][1] = copy.deepcopy(value["reports"][0]); successor_mutations.append(("successor-duplicate", value))
        value = copy.deepcopy(successor); value["reports"] = list(reversed(value["reports"])); successor_mutations.append(("successor-unsorted", value))
        value = copy.deepcopy(successor); value["observer_set_sequence"] = 0; successor_mutations.append(("successor-set-sequence", value))
        value = copy.deepcopy(successor); value["observer_set_sha256"] = "0" * 64; successor_mutations.append(("successor-set-digest", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observer_id"] = rotation_verify.REVOKED_OBSERVER_ID; successor_mutations.append(("revoked-observer-resurrection", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["checkpoint_sha256"] = "0" * 64; successor_mutations.append(("successor-checkpoint", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["checkpoint_statement_sha256"] = "0" * 64; successor_mutations.append(("successor-checkpoint-statement", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["monitor_set_sequence"] = 1; successor_mutations.append(("successor-monitor-set-sequence", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["monitor_set_sha256"] = "0" * 64; successor_mutations.append(("successor-monitor-set-digest", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["entry_count"] = 2; successor_mutations.append(("successor-entry-count", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["journal_sha256"] = "0" * 64; successor_mutations.append(("successor-journal", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["head_entry_sha256"] = "0" * 64; successor_mutations.append(("successor-head", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["previous_checkpoint_sha256"] = "0" * 64; successor_mutations.append(("successor-parent", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observer_rotation_journal_checkpoint_sha256"] = "0" * 64; successor_mutations.append(("successor-observer-rotation-journal-checkpoint", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observer_rotation_journal_checkpoint_statement_sha256"] = "0" * 64; successor_mutations.append(("successor-observer-rotation-journal-checkpoint-statement", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["observed_target_sha256"] = "0" * 64; successor_mutations.append(("successor-observed-target", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["activation_source_commit"] = "0" * 40; successor_mutations.append(("successor-source", value))
        value = copy.deepcopy(successor)
        sig = bytearray(material_verify.decode_signature(value["reports"][-1]["signature"]))
        sig[-1] ^= 1
        value["reports"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        successor_mutations.append(("successor-signature", value))
        value = copy.deepcopy(successor); value["production"] = True; successor_mutations.append(("successor-production", value))
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["production"] = True; successor_mutations.append(("successor-statement-production", value))
        value = copy.deepcopy(successor); value["reports"][0]["algorithm"] = "none"; successor_mutations.append(("successor-algorithm", value))

        for idx, (label, value) in enumerate(successor_mutations, start=1):
            fail(label, lambda value=value, idx=idx: run_with(81, write(f"s-{idx}.json", value))); cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(
            json.dumps(successor, indent=2) + "\n", encoding="utf-8"
        )
        fail("noncanonical-successor", lambda: run_with(81, noncanonical)); cases += 1
        fail("old-rust062-bundle-replay", lambda: run_with(81, base[78])); cases += 1
        fail(
            "observed-valid-successor-same-parent-fork",
            lambda: run_with(81, fork_path),
        ); cases += 1

    if cases != 40:
        raise AssertionError(f"unexpected RUST-063 selftest case count: {cases}")
    print(
        "RUST-063 monitor-rotation-journal observer rotation fail-closed contract: "
        "40/40 expected cases passed"
    )


if __name__ == "__main__":
    main()
