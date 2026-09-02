#!/usr/bin/env python3
"""RUST-043 detached availability/fail-closed contract."""
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
import rust_043_monitor_set_rotation_verify as rotation_verify


def W(path: Path, value: dict) -> None:
    path.write_bytes(material_verify.canonical(value))


def verify(paths: list[Path], source: str, floor: str) -> None:
    rotation_verify.verify(*paths, source, floor)


def replace(base: list[Path], index: int, value: dict, source: str, floor: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "changed.json"
        W(p, value)
        trial = list(base); trial[index] = p
        verify(trial, source, floor)


def expect_reject(label: str, base: list[Path], index: int, mutate, source: str, floor: str) -> None:
    _, original = floor_verify.load_canonical(base[index], label)
    changed = copy.deepcopy(original)
    mutate(changed)
    try:
        replace(base, index, changed, source, floor)
    except Exception:
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 31:
        raise SystemExit("usage: rust_043_monitor_set_rotation_selftest.py ... OLD_MONITOR_BUNDLE ROTATION AUTH SUCCESSOR FORK_SUCCESSOR SOURCE_SHA REQUIRED_FLOOR")
    source, floor = sys.argv[-2], sys.argv[-1]
    args = [Path(x) for x in sys.argv[1:-2]]
    base24 = args[:24]
    rotation_path, auth_path, successor_path, fork_successor_path = args[24:28]
    verify_paths = base24 + [rotation_path, auth_path, successor_path]
    verify(verify_paths, source, floor)

    # All 3 valid two-monitor predecessor authorization subsets remain accepted.
    _, auth = floor_verify.load_canonical(auth_path, "rotation auth")
    accepted = 0
    for rows in itertools.combinations(auth["monitors"], rotation_verify.THRESHOLD):
        changed = copy.deepcopy(auth); changed["monitors"] = list(rows)
        replace(verify_paths, 25, changed, source, floor); accepted += 1
    if accepted != 3: raise AssertionError("unexpected rotation auth subset count")
    print("[GREEN] RUST-043 predecessor authorization availability: 3/3 valid two-monitor subsets accepted")

    # All 3 valid two-monitor successor subsets remain accepted.
    _, successor = floor_verify.load_canonical(successor_path, "successor")
    accepted = 0
    for rows in itertools.combinations(successor["reports"], rotation_verify.THRESHOLD):
        changed = copy.deepcopy(successor); changed["reports"] = list(rows)
        replace(verify_paths, 26, changed, source, floor); accepted += 1
    if accepted != 3: raise AssertionError("unexpected successor subset count")
    print("[GREEN] RUST-043 successor monitor availability: 3/3 valid two-monitor subsets accepted")

    ri, ai, si = 24, 25, 26
    cases = [
        ("rotation-sequence", ri, lambda x: x.__setitem__("sequence", 0)),
        ("rotation-predecessor-set", ri, lambda x: x.__setitem__("from_set_sha256", "0" * 64)),
        ("rotation-successor-threshold", ri, lambda x: x["to_set"].__setitem__("threshold", 1)),
        ("rotation-revocation-omission", ri, lambda x: x.__setitem__("revoked_monitor_ids", [])),
        ("rotation-predecessor-bundle", ri, lambda x: x.__setitem__("predecessor_monitor_bundle_sha256", "0" * 64)),
        ("rotation-checkpoint", ri, lambda x: x.__setitem__("checkpoint_sha256", "0" * 64)),
        ("rotation-source", ri, lambda x: x.__setitem__("activation_source_commit", "0" * 40)),
        ("rotation-production", ri, lambda x: x.__setitem__("production", True)),
        ("auth-threshold", ai, lambda x: x.__setitem__("threshold", 1)),
        ("auth-below-threshold", ai, lambda x: x.__setitem__("monitors", x["monitors"][:1])),
        ("auth-duplicate", ai, lambda x: x.__setitem__("monitors", [x["monitors"][0], copy.deepcopy(x["monitors"][0])])),
        ("auth-unknown", ai, lambda x: x["monitors"][0].__setitem__("monitor_id", "unknown-monitor")),
        ("auth-signature", ai, lambda x: x["monitors"][0].__setitem__("signature", base64.b64encode(b"\0" * 64).decode())),
        ("auth-payload", ai, lambda x: x.__setitem__("payload_sha256", "0" * 64)),
        ("auth-production", ai, lambda x: x.__setitem__("production", True)),
        ("successor-threshold", si, lambda x: x.__setitem__("threshold", 1)),
        ("successor-below-threshold", si, lambda x: x.__setitem__("reports", x["reports"][:1])),
        ("successor-epoch-rollback", si, lambda x: x.__setitem__("monitor_set_sequence", 0)),
        ("successor-set-digest", si, lambda x: x.__setitem__("monitor_set_sha256", "0" * 64)),
        ("successor-duplicate", si, lambda x: x.__setitem__("reports", [x["reports"][0], copy.deepcopy(x["reports"][0])])),
        ("successor-source", si, lambda x: x["reports"][0]["statement"].__setitem__("activation_source_commit", "0" * 40)),
        ("successor-production", si, lambda x: x.__setitem__("production", True)),
        ("successor-statement-production", si, lambda x: x["reports"][0]["statement"].__setitem__("production", True)),
        ("successor-signature", si, lambda x: x["reports"][0].__setitem__("signature", base64.b64encode(b"\0" * 64).decode())),
    ]
    for label, index, mutate in cases:
        expect_reject(label, verify_paths, index, mutate, source, floor)

    for label, index in (("noncanonical-rotation", ri), ("noncanonical-auth", ai), ("noncanonical-successor", si)):
        _, value = floor_verify.load_canonical(verify_paths[index], label)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "nc.json"; p.write_text(json.dumps(value, indent=2), encoding="utf-8")
            trial = list(verify_paths); trial[index] = p
            try: verify(trial, source, floor)
            except Exception: print(f"[GREEN] mutation rejected: {label}")
            else: raise AssertionError(f"{label} unexpectedly accepted")

    # Old RUST-042 monitor bundle cannot replay as a sequence-1 successor bundle.
    trial = list(verify_paths); trial[si] = base24[-1]
    try: verify(trial, source, floor)
    except Exception: print("[GREEN] mutation rejected: old-rust042-monitor-bundle-replay")
    else: raise AssertionError("old RUST-042 monitor bundle replay accepted")

    # Two canonical successor monitors cannot hide one valid signed same-parent fork report.
    trial = list(verify_paths); trial[si] = fork_successor_path
    try: verify(trial, source, floor)
    except AssertionError as exc:
        if "observed successor monitor same-parent observer-journal fork" not in str(exc): raise
        print("[GREEN] mutation rejected: valid-signed-successor-monitor-split-view")
    else: raise AssertionError("valid signed successor monitor split view accepted")

    total = len(cases) + 5
    print(f"RUST-043 monitor-set rotation fail-closed contract: {total}/{total} expected cases passed")


if __name__ == "__main__":
    main()
