#!/usr/bin/env python3
"""RUST-032: TEST-ONLY external monotonic-floor consumer wrapper."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify
import rust_031_stdlib_trust_state_material_verify as trust_verify

EXTERNAL_FLOOR_SCHEMA = "axven-native-external-monotonic-floor-v1"
EXTERNAL_PROVIDER = "test-only-monotonic-floor-simulator"
EXTERNAL_FLOOR_KEYS = frozenset({
    "schema",
    "provider",
    "sequence",
    "scope",
    "key_id",
    "public_key",
    "activation_source_commit",
    "state_sha256",
    "production",
})
HEX = frozenset("0123456789abcdef")


def lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def load_canonical(path: Path, label: str) -> tuple[bytes, dict]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{label} must be a JSON object")
    if raw != material_verify.canonical(value):
        raise AssertionError(f"{label} is not canonical JSON")
    return raw, value


def parse_required_floor(text: str) -> int:
    if not isinstance(text, str) or not text or not text.isascii() or not text.isdigit():
        raise AssertionError("required external floor must be canonical decimal")
    value = int(text)
    if text != str(value):
        raise AssertionError("required external floor must not contain leading zeroes")
    return value


def validate_final_state(raw: bytes, value: dict, expected_source_sha: str) -> None:
    if frozenset(value) != trust_verify.STATE_KEYS or value.get("schema") != trust_verify.STATE_SCHEMA:
        raise AssertionError("unexpected RUST-031 final-state schema")
    if not isinstance(value.get("sequence"), int) or isinstance(value.get("sequence"), bool) or value["sequence"] < 0:
        raise AssertionError("invalid final-state sequence")
    if value["sequence"] != trust_verify.MINIMUM_SEQUENCE:
        raise AssertionError("unexpected RUST-031 final-state sequence")
    if value.get("scope") != trust_verify.MATERIAL_PAYLOAD_TYPE:
        raise AssertionError("unexpected final-state scope")
    if value.get("production") is not False:
        raise AssertionError("production trust state forbidden in TEST-ONLY RUST-032")
    if value.get("activation_source_commit") != expected_source_sha or not lower_hex(expected_source_sha, 40):
        raise AssertionError("final-state activation source mismatch")
    if value.get("key_id") != trust_verify.NEW_KEY_ID:
        raise AssertionError("unexpected RUST-031 final-state key id")
    if value.get("public_key") != trust_verify.NEW_PUBLIC_KEY.hex():
        raise AssertionError("unexpected RUST-031 final-state public key")
    if not lower_hex(value.get("predecessor_sha256"), 64) or not lower_hex(value.get("transition_sha256"), 64):
        raise AssertionError("invalid final-state chain digest")
    if raw != material_verify.canonical(value):
        raise AssertionError("final trust state is not canonical JSON")


def validate_external_floor(
    floor_raw: bytes,
    floor: dict,
    final_raw: bytes,
    final_state: dict,
    expected_source_sha: str,
    required_floor: int,
) -> None:
    if frozenset(floor) != EXTERNAL_FLOOR_KEYS or floor.get("schema") != EXTERNAL_FLOOR_SCHEMA:
        raise AssertionError("unexpected external-floor schema")
    if floor.get("provider") != EXTERNAL_PROVIDER:
        raise AssertionError("unexpected external-floor provider")
    if floor.get("production") is not False:
        raise AssertionError("production external floor forbidden in TEST-ONLY RUST-032")
    if floor.get("scope") != trust_verify.MATERIAL_PAYLOAD_TYPE:
        raise AssertionError("unexpected external-floor scope")
    sequence = floor.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise AssertionError("invalid external-floor sequence")
    if sequence < required_floor:
        raise AssertionError("external floor sequence below required floor")
    if final_state["sequence"] < sequence:
        raise AssertionError("final trust state below external floor")
    if floor.get("key_id") != final_state["key_id"] or floor.get("public_key") != final_state["public_key"]:
        raise AssertionError("external floor trust root does not match accepted state")
    if floor.get("activation_source_commit") != expected_source_sha:
        raise AssertionError("external-floor activation source mismatch")
    if floor.get("state_sha256") != hashlib.sha256(final_raw).hexdigest():
        raise AssertionError("external-floor state digest mismatch")
    if floor_raw != material_verify.canonical(floor):
        raise AssertionError("external floor is not canonical JSON")


def verify(final_state_path: Path, external_floor_path: Path, expected_source_sha: str, required_floor_text: str) -> None:
    required_floor = parse_required_floor(required_floor_text)
    final_raw, final_state = load_canonical(final_state_path, "final trust state")
    floor_raw, floor = load_canonical(external_floor_path, "external monotonic floor")
    validate_final_state(final_raw, final_state, expected_source_sha)
    validate_external_floor(floor_raw, floor, final_raw, final_state, expected_source_sha, required_floor)
    print(
        "RUST-032 external monotonic floor: GREEN "
        f"source={expected_source_sha} required={required_floor} external={floor['sequence']} state={final_state['sequence']}"
    )


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def selftest(final_state_path: Path, external_floor_path: Path, expected_source_sha: str, required_floor_text: str) -> None:
    verify(final_state_path, external_floor_path, expected_source_sha, required_floor_text)
    _, final_state = load_canonical(final_state_path, "final trust state")
    _, floor = load_canonical(external_floor_path, "external monotonic floor")
    required_floor = parse_required_floor(required_floor_text)
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        expect_failure(
            "required-floor-advance",
            lambda: verify(final_state_path, external_floor_path, expected_source_sha, str(required_floor + 1)),
        ); cases += 1

        value = copy.deepcopy(floor); value["sequence"] = max(0, required_floor - 1)
        bad = write_obj("floor-downgrade.json", value)
        expect_failure("external-floor-downgrade", lambda: verify(final_state_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(final_state); value["sequence"] = max(0, floor["sequence"] - 1)
        bad_state = write_obj("stale-final-state.json", value)
        expect_failure("stale-final-state", lambda: verify(bad_state, external_floor_path, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["state_sha256"] = "0" * 64
        bad = write_obj("bad-state-digest.json", value)
        expect_failure("state-digest", lambda: verify(final_state_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["key_id"] = "unexpected-key"
        bad = write_obj("bad-key-id.json", value)
        expect_failure("key-id", lambda: verify(final_state_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["public_key"] = "0" * 64
        bad = write_obj("bad-public-key.json", value)
        expect_failure("public-key", lambda: verify(final_state_path, bad, expected_source_sha, required_floor_text)); cases += 1

        expect_failure("activation-source", lambda: verify(final_state_path, external_floor_path, "0" * 40, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["production"] = True
        bad = write_obj("production-floor.json", value)
        expect_failure("production-floor", lambda: verify(final_state_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["provider"] = "ambient-file"
        bad = write_obj("wrong-provider.json", value)
        expect_failure("provider", lambda: verify(final_state_path, bad, expected_source_sha, required_floor_text)); cases += 1

        noncanonical_floor = root / "noncanonical-floor.json"
        noncanonical_floor.write_text(json.dumps(floor, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-floor", lambda: verify(final_state_path, noncanonical_floor, expected_source_sha, required_floor_text)); cases += 1

        noncanonical_state = root / "noncanonical-state.json"
        noncanonical_state.write_text(json.dumps(final_state, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-state", lambda: verify(noncanonical_state, external_floor_path, expected_source_sha, required_floor_text)); cases += 1

    if cases != 11:
        raise AssertionError(f"unexpected RUST-032 selftest case count: {cases}")
    print("RUST-032 external monotonic floor fail-closed contract: 11/11 expected cases passed")


def main() -> None:
    if len(sys.argv) != 6 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_032_external_monotonic_floor_verify.py verify|selftest "
            "FINAL_STATE EXTERNAL_FLOOR EXPECTED_SOURCE_SHA REQUIRED_FLOOR"
        )
    fn = verify if sys.argv[1] == "verify" else selftest
    fn(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5])


if __name__ == "__main__":
    main()
