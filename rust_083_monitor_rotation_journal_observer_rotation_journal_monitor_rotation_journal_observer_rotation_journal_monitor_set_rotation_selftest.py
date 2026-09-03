#!/usr/bin/env python3
"""RUST-083 detached monitor-set rotation availability/fail-closed selftest."""
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
import rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify as monitor_verify
import rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify as rotation_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def replacement_for(field: str):
    if field == "activation_source_commit":
        return "0" * 40
    if field in {"observer_set_sequence", "entry_count"}:
        return 1
    return "0" * 64


def main() -> None:
    if len(sys.argv) != 141:
        raise SystemExit(
            "usage: rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_selftest.py "
            "... OLD_BUNDLE ROTATION AUTH SUCCESSOR FORK_SUCCESSOR SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 137:
        raise AssertionError("unexpected RUST-083 selftest base path count")

    rotation_verify.verify(*base, source_sha, required_floor)
    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        base[132], "RUST-081 final observer rotation checkpoint"
    )
    rotation_raw, rotation = floor_verify.load_canonical(
        base[134], "RUST-083 monitor-set rotation"
    )
    _, auth = floor_verify.load_canonical(
        base[135], "RUST-083 rotation authorization"
    )
    _, successor = floor_verify.load_canonical(
        base[136], "RUST-083 successor monitor bundle"
    )
    target = monitor_verify.checkpoint_target(checkpoint_raw, checkpoint["statement"])
    if target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-083 selftest target source mismatch")

    auth_ok = 0
    for subset in itertools.combinations(auth["monitors"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(auth)
        candidate["monitors"] = list(subset)
        rotation_verify.validate_rotation_auth(candidate, rotation_raw)
        auth_ok += 1
    if auth_ok != 3:
        raise AssertionError("unexpected RUST-083 predecessor authorization subset count")
    print("[GREEN] RUST-083 predecessor authorization availability: 3/3 valid two-monitor subsets accepted")

    successor_ok = 0
    for subset in itertools.combinations(successor["reports"], rotation_verify.THRESHOLD):
        candidate = copy.deepcopy(successor)
        candidate["reports"] = list(subset)
        rotation_verify.validate_successor_bundle(candidate, target)
        successor_ok += 1
    if successor_ok != 3:
        raise AssertionError("unexpected RUST-083 successor monitoring subset count")
    print("[GREEN] RUST-083 successor monitoring availability: 3/3 valid two-monitor subsets accepted")

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

        value = copy.deepcopy(rotation); value["sequence"] = 0
        fail("rotation-sequence", lambda: run_with(134, write("a.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["from_set_sha256"] = "0" * 64
        fail("rotation-predecessor-set", lambda: run_with(134, write("b.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["to_set"]["threshold"] = 1
        fail("rotation-successor-set", lambda: run_with(134, write("c.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["revoked_monitor_ids"] = []
        fail("rotation-revocation", lambda: run_with(134, write("d.json", value))); cases += 1
        value = copy.deepcopy(rotation); value["predecessor_monitor_bundle_sha256"] = "0" * 64
        fail("rotation-predecessor-bundle", lambda: run_with(134, write("e.json", value))); cases += 1

        for idx, field in enumerate(sorted(monitor_verify.TARGET_KEYS)):
            value = copy.deepcopy(rotation)
            value[field] = replacement_for(field)
            fail(
                f"rotation-target-{field}",
                lambda v=value, n=f"rt{idx}.json": run_with(134, write(n, v)),
            )
            cases += 1

        value = copy.deepcopy(rotation); value["production"] = True
        fail("rotation-production", lambda: run_with(134, write("f.json", value))); cases += 1

        value = copy.deepcopy(auth); value["threshold"] = 1
        fail("auth-threshold", lambda: run_with(135, write("g.json", value))); cases += 1
        value = copy.deepcopy(auth); value["monitors"] = value["monitors"][:1]
        fail("auth-below-threshold", lambda: run_with(135, write("h.json", value))); cases += 1
        value = copy.deepcopy(auth); value["monitors"] = [value["monitors"][0], copy.deepcopy(value["monitors"][0])]
        fail("auth-duplicate", lambda: run_with(135, write("i.json", value))); cases += 1
        value = copy.deepcopy(auth); value["monitors"] = list(reversed(value["monitors"]))
        fail("auth-unsorted", lambda: run_with(135, write("j.json", value))); cases += 1
        value = copy.deepcopy(auth); value["payload_sha256"] = "0" * 64
        fail("auth-payload", lambda: run_with(135, write("k.json", value))); cases += 1
        value = copy.deepcopy(auth)
        sig = bytearray(material_verify.decode_signature(value["monitors"][0]["signature"])); sig[0] ^= 1
        value["monitors"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        fail("auth-signature", lambda: run_with(135, write("l.json", value))); cases += 1

        value = copy.deepcopy(successor); value["threshold"] = 1
        fail("successor-threshold", lambda: run_with(136, write("m.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"] = value["reports"][:1]
        fail("successor-below-threshold", lambda: run_with(136, write("n.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][1] = copy.deepcopy(value["reports"][0])
        fail("successor-duplicate", lambda: run_with(136, write("o.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"] = list(reversed(value["reports"]))
        fail("successor-unsorted", lambda: run_with(136, write("p.json", value))); cases += 1
        value = copy.deepcopy(successor); value["monitor_set_sequence"] = 0
        fail("successor-set-sequence", lambda: run_with(136, write("q.json", value))); cases += 1
        value = copy.deepcopy(successor); value["monitor_set_sha256"] = "0" * 64
        fail("successor-set-digest", lambda: run_with(136, write("r.json", value))); cases += 1
        value = copy.deepcopy(successor); value["reports"][0]["statement"]["monitor_id"] = rotation_verify.REVOKED_MONITOR_ID
        fail("revoked-monitor-resurrection", lambda: run_with(136, write("s.json", value))); cases += 1

        for idx, field in enumerate(sorted(monitor_verify.TARGET_KEYS)):
            value = copy.deepcopy(successor)
            value["reports"][0]["statement"][field] = replacement_for(field)
            fail(
                f"successor-target-{field}",
                lambda v=value, n=f"st{idx}.json": run_with(136, write(n, v)),
            )
            cases += 1

        value = copy.deepcopy(successor)
        sig = bytearray(material_verify.decode_signature(value["reports"][-1]["signature"])); sig[-1] ^= 1
        value["reports"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        fail("successor-signature", lambda: run_with(136, write("t.json", value))); cases += 1
        value = copy.deepcopy(successor); value["production"] = True
        fail("successor-production", lambda: run_with(136, write("u.json", value))); cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(successor, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-successor", lambda: run_with(136, noncanonical)); cases += 1
        fail("old-rust082-bundle-replay", lambda: run_with(136, base[133])); cases += 1
        fail("observed-valid-successor-same-parent-fork", lambda: run_with(136, fork_path)); cases += 1

    if cases != 48:
        raise AssertionError(f"unexpected RUST-083 selftest case count: {cases}")
    print("RUST-083 monitor-set rotation fail-closed contract: 48/48 expected cases passed")


if __name__ == "__main__":
    main()
