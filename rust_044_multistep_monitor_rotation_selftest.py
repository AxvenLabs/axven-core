#!/usr/bin/env python3
"""RUST-044 detached multi-step monitor rotation availability/fail-closed contract."""
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
import rust_044_multistep_monitor_rotation_verify as rotation_verify


def write_canonical(path: Path, value: dict) -> None:
    path.write_bytes(material_verify.canonical(value))


def invoke(paths: list[Path], source: str, floor: str) -> None:
    rotation_verify.verify(*paths, source, floor)


def mutate_doc(paths: list[Path], index: int, label: str, source: str, floor: str, fn) -> None:
    _, original = floor_verify.load_canonical(paths[index], label)
    changed = copy.deepcopy(original); fn(changed)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / f"{label}.json"; write_canonical(p, changed)
        trial = list(paths); trial[index] = p
        try:
            invoke(trial, source, floor)
        except Exception:
            print(f"[GREEN] mutation rejected: {label}")
            return
        raise AssertionError(f"mutation unexpectedly accepted: {label}")


def main() -> None:
    if len(sys.argv) != 34:
        raise SystemExit("usage: rust_044_multistep_monitor_rotation_selftest.py ... SECOND_ROT AUTH FINAL FORK SOURCE_SHA REQUIRED_FLOOR")
    source, floor = sys.argv[-2], sys.argv[-1]
    raw = [Path(v) for v in sys.argv[1:-2]]
    base = raw[:27]
    second_rotation_path, second_auth_path, final_bundle_path, fork_bundle_path = raw[27:31]
    verify_paths = base + [second_rotation_path, second_auth_path, final_bundle_path]
    invoke(verify_paths, source, floor)

    _, auth = floor_verify.load_canonical(second_auth_path, "second auth")
    accepted_auth = 0
    for rows in itertools.combinations(auth["monitors"], rotation_verify.THRESHOLD):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"auth.json"; subset=copy.deepcopy(auth); subset["monitors"]=list(rows); write_canonical(p, subset)
            invoke(base + [second_rotation_path, p, final_bundle_path], source, floor); accepted_auth += 1
    assert accepted_auth == 3
    print("[GREEN] RUST-044 second authorization availability: 3/3 valid two-monitor subsets accepted")

    _, final_bundle = floor_verify.load_canonical(final_bundle_path, "final bundle")
    accepted_final = 0
    for rows in itertools.combinations(final_bundle["reports"], rotation_verify.THRESHOLD):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"final.json"; subset=copy.deepcopy(final_bundle); subset["reports"]=list(rows); write_canonical(p, subset)
            invoke(base + [second_rotation_path, second_auth_path, p], source, floor); accepted_final += 1
    assert accepted_final == 3
    print("[GREEN] RUST-044 final monitor availability: 3/3 valid two-monitor subsets accepted")

    cases = [
        (27, "rotation-schema", lambda d: d.__setitem__("schema", "bad")),
        (27, "rotation-sequence", lambda d: d.__setitem__("sequence", 1)),
        (27, "predecessor-set", lambda d: d.__setitem__("from_set_sha256", "0"*64)),
        (27, "final-set", lambda d: d["to_set"].__setitem__("sequence", 3)),
        (27, "cumulative-revocation", lambda d: d.__setitem__("cumulative_revoked_monitor_ids", d["cumulative_revoked_monitor_ids"][:1])),
        (27, "predecessor-rotation", lambda d: d.__setitem__("predecessor_rotation_sha256", "0"*64)),
        (27, "predecessor-auth", lambda d: d.__setitem__("predecessor_rotation_auth_sha256", "0"*64)),
        (27, "predecessor-successor", lambda d: d.__setitem__("predecessor_successor_bundle_sha256", "0"*64)),
        (27, "checkpoint-binding", lambda d: d.__setitem__("checkpoint_sha256", "0"*64)),
        (27, "rotation-source", lambda d: d.__setitem__("activation_source_commit", "0"*40)),
        (27, "rotation-production", lambda d: d.__setitem__("production", True)),
        (28, "auth-schema", lambda d: d.__setitem__("schema", "bad")),
        (28, "auth-threshold", lambda d: d.__setitem__("threshold", 1)),
        (28, "auth-payload", lambda d: d.__setitem__("payload_sha256", "0"*64)),
        (28, "auth-below-threshold", lambda d: d.__setitem__("monitors", d["monitors"][:1])),
        (28, "auth-duplicate", lambda d: d.__setitem__("monitors", [d["monitors"][0], copy.deepcopy(d["monitors"][0])])),
        (28, "auth-unknown", lambda d: d["monitors"][0].__setitem__("monitor_id", rotation_verify.CUMULATIVE_REVOKED_MONITOR_IDS[0])),
        (28, "auth-signature", lambda d: d["monitors"][0].__setitem__("signature", base64.b64encode(b"\0"*64).decode())),
        (29, "final-schema", lambda d: d.__setitem__("schema", "bad")),
        (29, "final-epoch", lambda d: d.__setitem__("monitor_set_sequence", 1)),
        (29, "final-set-digest", lambda d: d.__setitem__("monitor_set_sha256", "0"*64)),
        (29, "final-threshold", lambda d: d.__setitem__("threshold", 1)),
        (29, "final-production", lambda d: d.__setitem__("production", True)),
        (29, "final-below-threshold", lambda d: d.__setitem__("reports", d["reports"][:1])),
        (29, "final-duplicate", lambda d: d.__setitem__("reports", [d["reports"][0], copy.deepcopy(d["reports"][0])])),
        (29, "final-revoked-monitor", lambda d: d["reports"][0]["statement"].__setitem__("monitor_id", rotation_verify.CUMULATIVE_REVOKED_MONITOR_IDS[1])),
        (29, "final-statement-epoch", lambda d: d["reports"][0]["statement"].__setitem__("monitor_set_sequence", 1)),
        (29, "final-checkpoint", lambda d: d["reports"][0]["statement"].__setitem__("checkpoint_sha256", "0"*64)),
        (29, "final-journal", lambda d: d["reports"][0]["statement"].__setitem__("journal_sha256", "0"*64)),
        (29, "final-previous-checkpoint", lambda d: d["reports"][0]["statement"].__setitem__("previous_checkpoint_sha256", "0"*64)),
        (29, "final-source", lambda d: d["reports"][0]["statement"].__setitem__("activation_source_commit", "0"*40)),
        (29, "final-statement-production", lambda d: d["reports"][0]["statement"].__setitem__("production", True)),
        (29, "final-signature", lambda d: d["reports"][0].__setitem__("signature", base64.b64encode(b"\0"*64).decode())),
    ]
    for index, label, fn in cases:
        mutate_doc(verify_paths, index, label, source, floor, fn)

    try:
        invoke(base + [second_rotation_path, second_auth_path, base[26]], source, floor)
    except Exception:
        print("[GREEN] mutation rejected: old-rust043-final-bundle-replay")
    else:
        raise AssertionError("old RUST-043 successor bundle replay unexpectedly accepted")

    try:
        invoke(base + [second_rotation_path, second_auth_path, fork_bundle_path], source, floor)
    except AssertionError as exc:
        if "observed final monitor same-parent observer-journal fork" not in str(exc):
            raise
        print("[GREEN] mutation rejected: signed-final-same-parent-split-view")
    else:
        raise AssertionError("signed final monitor split view unexpectedly accepted")

    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/"noncanonical.json"; p.write_text(json.dumps(final_bundle, indent=2), encoding="utf-8")
        try:
            invoke(base + [second_rotation_path, second_auth_path, p], source, floor)
        except Exception:
            print("[GREEN] mutation rejected: noncanonical-final-bundle")
        else:
            raise AssertionError("noncanonical final bundle accepted")

    total = len(cases) + 3
    print(f"RUST-044 multi-step monitor rotation fail-closed contract: {total}/{total} expected cases passed")


if __name__ == "__main__":
    main()
