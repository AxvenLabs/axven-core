#!/usr/bin/env python3
"""RUST-128 detached second monitor-set rotation availability/fail-closed selftest."""
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
import rust_126_rust125_checkpoint_monitor_verify as monitor_verify
import rust_128_multistep_rust126_checkpoint_monitor_rotation_verify as rotation2_verify


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
    if field in {"monitor_set_sequence", "entry_count"}:
        return 1
    return "0" * 64


def main() -> None:
    if len(sys.argv) != 265:
        raise SystemExit(
            "usage: rust_128_multistep_rust126_checkpoint_monitor_rotation_selftest.py "
            "... FINAL_BUNDLE FORK_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 261:
        raise AssertionError("unexpected RUST-128 selftest base path count")

    rotation2_verify.verify(*base, source_sha, required_floor)
    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        base[253], "RUST-125 final monitor rotation checkpoint"
    )
    second_rotation_raw, second_rotation = floor_verify.load_canonical(
        base[258], "RUST-128 second monitor rotation"
    )
    _, second_auth = floor_verify.load_canonical(
        base[259], "RUST-128 second rotation authorization"
    )
    _, final_bundle = floor_verify.load_canonical(
        base[260], "RUST-128 final monitor bundle"
    )
    target = monitor_verify.checkpoint_target(checkpoint_raw, checkpoint["statement"])
    if target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-128 selftest target source mismatch")

    auth_ok = 0
    for subset in itertools.combinations(second_auth["monitors"], rotation2_verify.THRESHOLD):
        candidate = copy.deepcopy(second_auth)
        candidate["monitors"] = list(subset)
        rotation2_verify.validate_rotation_auth(candidate, second_rotation_raw)
        auth_ok += 1
    if auth_ok != 3:
        raise AssertionError("unexpected RUST-128 authorization subset count")
    print("[GREEN] RUST-128 predecessor authorization availability: 3/3 valid two-monitor subsets accepted")

    final_ok = 0
    for subset in itertools.combinations(final_bundle["reports"], rotation2_verify.THRESHOLD):
        candidate = copy.deepcopy(final_bundle)
        candidate["reports"] = list(subset)
        rotation2_verify.validate_final_bundle(candidate, target)
        final_ok += 1
    if final_ok != 3:
        raise AssertionError("unexpected RUST-128 final monitoring subset count")
    print("[GREEN] RUST-128 final monitoring availability: 3/3 valid two-monitor subsets accepted")

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
            rotation2_verify.verify(*paths, source_sha, required_floor)

        value = copy.deepcopy(second_rotation); value["sequence"] = 1
        fail("rotation-sequence-rollback", lambda: run_with(258, write("a.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["from_set_sha256"] = "0" * 64
        fail("rotation-predecessor-set", lambda: run_with(258, write("b.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["to_set"]["threshold"] = 1
        fail("rotation-final-set", lambda: run_with(258, write("c.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["cumulative_revoked_monitor_ids"] = [rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS[0]]
        fail("rotation-cumulative-revocation", lambda: run_with(258, write("d.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["predecessor_rotation_sha256"] = "0" * 64
        fail("rotation-predecessor-rotation", lambda: run_with(258, write("e.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["predecessor_rotation_auth_sha256"] = "0" * 64
        fail("rotation-predecessor-auth", lambda: run_with(258, write("f.json", value))); cases += 1
        value = copy.deepcopy(second_rotation); value["predecessor_successor_bundle_sha256"] = "0" * 64
        fail("rotation-predecessor-successor", lambda: run_with(258, write("g.json", value))); cases += 1

        for idx, field in enumerate(sorted(monitor_verify.TARGET_KEYS)):
            value = copy.deepcopy(second_rotation)
            value[field] = replacement_for(field)
            fail(
                f"rotation-target-{field}",
                lambda v=value, n=f"rt{idx}.json": run_with(258, write(n, v)),
            )
            cases += 1

        value = copy.deepcopy(second_rotation); value["production"] = True
        fail("rotation-production", lambda: run_with(258, write("h.json", value))); cases += 1

        value = copy.deepcopy(second_auth); value["threshold"] = 1
        fail("auth-threshold", lambda: run_with(259, write("i.json", value))); cases += 1
        value = copy.deepcopy(second_auth); value["monitors"] = value["monitors"][:1]
        fail("auth-below-threshold", lambda: run_with(259, write("j.json", value))); cases += 1
        value = copy.deepcopy(second_auth); value["monitors"] = [value["monitors"][0], copy.deepcopy(value["monitors"][0])]
        fail("auth-duplicate", lambda: run_with(259, write("k.json", value))); cases += 1
        value = copy.deepcopy(second_auth); value["monitors"] = list(reversed(value["monitors"]))
        fail("auth-unsorted", lambda: run_with(259, write("l.json", value))); cases += 1
        value = copy.deepcopy(second_auth); value["payload_sha256"] = "0" * 64
        fail("auth-payload", lambda: run_with(259, write("m.json", value))); cases += 1
        value = copy.deepcopy(second_auth)
        sig = bytearray(material_verify.decode_signature(value["monitors"][0]["signature"])); sig[0] ^= 1
        value["monitors"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        fail("auth-signature", lambda: run_with(259, write("n.json", value))); cases += 1

        value = copy.deepcopy(final_bundle); value["threshold"] = 1
        fail("final-threshold", lambda: run_with(260, write("o.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"] = value["reports"][:1]
        fail("final-below-threshold", lambda: run_with(260, write("p.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][1] = copy.deepcopy(value["reports"][0])
        fail("final-duplicate", lambda: run_with(260, write("q.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"] = list(reversed(value["reports"]))
        fail("final-unsorted", lambda: run_with(260, write("r.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["final_monitor_set_sequence"] = 1
        fail("final-set-sequence", lambda: run_with(260, write("s.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["final_monitor_set_sha256"] = "0" * 64
        fail("final-set-digest", lambda: run_with(260, write("t.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["final_monitor_set_sequence"] = 1
        fail("final-statement-set-sequence", lambda: run_with(260, write("u.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["final_monitor_set_sha256"] = "0" * 64
        fail("final-statement-set-digest", lambda: run_with(260, write("v.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["monitor_id"] = rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS[0]
        fail("revoked-m1-resurrection", lambda: run_with(260, write("w.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["reports"][0]["statement"]["monitor_id"] = rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS[1]
        fail("revoked-m2-resurrection", lambda: run_with(260, write("x.json", value))); cases += 1

        for idx, field in enumerate(sorted(monitor_verify.TARGET_KEYS)):
            value = copy.deepcopy(final_bundle)
            value["reports"][0]["statement"][field] = replacement_for(field)
            fail(
                f"final-target-{field}",
                lambda v=value, n=f"ft{idx}.json": run_with(260, write(n, v)),
            )
            cases += 1

        value = copy.deepcopy(final_bundle)
        sig = bytearray(material_verify.decode_signature(value["reports"][-1]["signature"])); sig[-1] ^= 1
        value["reports"][-1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        fail("final-signature", lambda: run_with(260, write("y.json", value))); cases += 1
        value = copy.deepcopy(final_bundle); value["production"] = True
        fail("final-production", lambda: run_with(260, write("z.json", value))); cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(final_bundle, indent=2) + "\n", encoding="utf-8")
        fail("noncanonical-final-bundle", lambda: run_with(260, noncanonical)); cases += 1
        fail("first-successor-replay", lambda: run_with(260, base[257])); cases += 1
        fail("observed-valid-final-same-parent-fork", lambda: run_with(260, fork_path)); cases += 1

    if cases != 53:
        raise AssertionError(f"unexpected RUST-128 selftest case count: {cases}")
    print("RUST-128 multi-step monitor rotation fail-closed contract: 53/53 expected cases passed")


if __name__ == "__main__":
    main()
