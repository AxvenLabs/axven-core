#!/usr/bin/env python3
"""RUST-030: stdlib-only detached monotonic TEST-ONLY trust-state verifier."""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

STATE_SCHEMA = "axven-native-trust-state-v1"
TRANSITION_SCHEMA = "axven-native-trust-transition-v1"
TRANSITION_ENVELOPE_SCHEMA = "axven-native-trust-transition-envelope-v1"
TRANSITION_PAYLOAD_TYPE = "application/vnd.axven.native-trust-transition.v1+json"
MATERIAL_PAYLOAD_TYPE = "application/vnd.axven.native-build-materials.v1+json"
TRANSITION_DOMAIN = b"AXVEN_NATIVE_TRUST_TRANSITION_V1\x00"
ALGORITHM = "ed25519"
OLD_KEY_ID = "rust-026-test-only-ed25519-v1"
OLD_PUBLIC_KEY = bytes.fromhex("4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064")
NEW_KEY_ID = "rust-028-test-only-ed25519-v2"
NEW_PUBLIC_KEY = bytes.fromhex("158d55a155c9191d0783d48c1a1a1531fe65a783356c5b221e6952e57d58fdb3")
MINIMUM_SEQUENCE = 1
HEX = frozenset("0123456789abcdef")

STATE_KEYS = frozenset(
    {
        "schema",
        "sequence",
        "scope",
        "key_id",
        "public_key",
        "activation_source_commit",
        "predecessor_sha256",
        "transition_sha256",
        "production",
    }
)
TRANSITION_KEYS = frozenset(
    {
        "schema",
        "sequence",
        "scope",
        "from_key_id",
        "from_public_key",
        "to_key_id",
        "to_public_key",
        "activation_source_commit",
        "production",
    }
)
ENVELOPE_KEYS = frozenset(
    {"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"}
)

# RFC 8032 / Ed25519 arithmetic. Verification only: no seed/private-key API.
FIELD_Q = 2**255 - 19
GROUP_L = 2**252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, FIELD_Q - 2, FIELD_Q)) % FIELD_Q
SQRT_M1 = pow(2, (FIELD_Q - 1) // 4, FIELD_Q)
IDENTITY = (0, 1, 1, 0)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(ch in HEX for ch in value)
    )


def assert_regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"{label} must be a real regular file")


def load_canonical(path: Path, label: str) -> tuple[bytes, dict]:
    assert_regular(path, label)
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or raw != canonical(value):
        raise AssertionError(f"{label} must be canonical JSON object")
    return raw, value


def decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise AssertionError("signature must be base64 text")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise AssertionError("invalid base64 signature") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise AssertionError("invalid/non-canonical Ed25519 signature")
    return raw


def signed_message(payload: bytes) -> bytes:
    return TRANSITION_DOMAIN + len(payload).to_bytes(8, "big") + payload


def _recover_x(y: int, sign: int) -> int:
    if y >= FIELD_Q:
        raise AssertionError("non-canonical Ed25519 y coordinate")
    x2 = (
        (y * y - 1)
        * pow((CURVE_D * y * y + 1) % FIELD_Q, FIELD_Q - 2, FIELD_Q)
    ) % FIELD_Q
    x = pow(x2, (FIELD_Q + 3) // 8, FIELD_Q)
    if (x * x - x2) % FIELD_Q:
        x = (x * SQRT_M1) % FIELD_Q
    if (x * x - x2) % FIELD_Q:
        raise AssertionError("invalid Ed25519 point")
    if x == 0 and sign:
        raise AssertionError("non-canonical Ed25519 negative zero")
    if (x & 1) != sign:
        x = FIELD_Q - x
    return x


def _to_affine(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    if z % FIELD_Q == 0:
        raise AssertionError("invalid projective Ed25519 point")
    inv_z = pow(z, FIELD_Q - 2, FIELD_Q)
    return (x * inv_z) % FIELD_Q, (y * inv_z) % FIELD_Q


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y = _to_affine(point)
    raw = y | ((x & 1) << 255)
    return raw.to_bytes(32, "little")


def _decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise AssertionError("invalid Ed25519 point length")
    raw = int.from_bytes(encoded, "little")
    sign = (raw >> 255) & 1
    y = raw & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if (-x * x + y * y - 1 - CURVE_D * x * x * y * y) % FIELD_Q:
        raise AssertionError("Ed25519 point is off curve")
    point = (x, y, 1, (x * y) % FIELD_Q)
    if _encode_point(point) != encoded:
        raise AssertionError("non-canonical Ed25519 point encoding")
    return point


def _add(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % FIELD_Q
    b = ((y1 + x1) * (y2 + x2)) % FIELD_Q
    c = (2 * CURVE_D * t1 * t2) % FIELD_Q
    d = (2 * z1 * z2) % FIELD_Q
    e = (b - a) % FIELD_Q
    f = (d - c) % FIELD_Q
    g = (d + c) % FIELD_Q
    h = (b + a) % FIELD_Q
    return (
        e * f % FIELD_Q,
        g * h % FIELD_Q,
        f * g % FIELD_Q,
        e * h % FIELD_Q,
    )


def _scalar_mult(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    if scalar < 0:
        raise AssertionError("negative Ed25519 scalar")
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _points_equal(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (
        (x1 * z2 - x2 * z1) % FIELD_Q == 0
        and (y1 * z2 - y2 * z1) % FIELD_Q == 0
    )


def _require_prime_subgroup(
    point: tuple[int, int, int, int], label: str
) -> None:
    if _points_equal(point, IDENTITY):
        raise AssertionError(f"{label} must not be the Ed25519 identity")
    if not _points_equal(_scalar_mult(point, GROUP_L), IDENTITY):
        raise AssertionError(f"{label} is outside the Ed25519 prime-order subgroup")


_BASE_Y = (4 * pow(5, FIELD_Q - 2, FIELD_Q)) % FIELD_Q
_BASE_X = _recover_x(_BASE_Y, 0)
BASE_POINT = (_BASE_X, _BASE_Y, 1, (_BASE_X * _BASE_Y) % FIELD_Q)


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        raise AssertionError("invalid Ed25519 key/signature length")
    a = _decode_point(public_key)
    r = _decode_point(signature[:32])
    _require_prime_subgroup(a, "public key")
    _require_prime_subgroup(r, "signature R")
    s = int.from_bytes(signature[32:], "little")
    if s >= GROUP_L:
        raise AssertionError("non-canonical Ed25519 S scalar")
    k = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
        )
        % GROUP_L
    )
    if not _points_equal(
        _scalar_mult(BASE_POINT, s), _add(r, _scalar_mult(a, k))
    ):
        raise AssertionError("Ed25519 signature mismatch")


def rfc8032_selftest() -> None:
    # RFC 8032 test vector 1: empty message.
    public_key = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    ed25519_verify(public_key, signature, b"")
    mutated = bytearray(signature)
    mutated[0] ^= 1
    try:
        ed25519_verify(public_key, bytes(mutated), b"")
    except AssertionError:
        print("RUST-030 RFC 8032 Ed25519 known-answer contract: GREEN")
        return
    raise AssertionError("mutated RFC 8032 signature unexpectedly accepted")


def validate_state(value: dict, expected_source_sha: str | None = None) -> None:
    if frozenset(value) != STATE_KEYS or value["schema"] != STATE_SCHEMA:
        raise AssertionError("unexpected trust-state schema/fields")
    seq = value["sequence"]
    if type(seq) is not int or seq < 0:
        raise AssertionError("invalid trust-state sequence")
    if (
        value["scope"] != MATERIAL_PAYLOAD_TYPE
        or value["production"] is not False
    ):
        raise AssertionError("unexpected trust-state scope/production flag")
    if seq == 0:
        if (
            value["key_id"] != OLD_KEY_ID
            or value["public_key"] != OLD_PUBLIC_KEY.hex()
        ):
            raise AssertionError("genesis trust root mismatch")
        if any(
            value[name] is not None
            for name in (
                "activation_source_commit",
                "predecessor_sha256",
                "transition_sha256",
            )
        ):
            raise AssertionError(
                "genesis trust state must not claim predecessor/transition"
            )
    elif seq == 1:
        if (
            value["key_id"] != NEW_KEY_ID
            or value["public_key"] != NEW_PUBLIC_KEY.hex()
        ):
            raise AssertionError("sequence-1 trust root mismatch")
        if not lower_hex(value["activation_source_commit"], 40):
            raise AssertionError("invalid sequence-1 activation source")
        if (
            expected_source_sha is not None
            and value["activation_source_commit"] != expected_source_sha
        ):
            raise AssertionError("sequence-1 activation source mismatch")
        if not lower_hex(value["predecessor_sha256"], 64) or not lower_hex(
            value["transition_sha256"], 64
        ):
            raise AssertionError("invalid sequence-1 chain digest")
    else:
        raise AssertionError(
            "RUST-030 only authorizes trust-state sequences 0 and 1"
        )


def validate_transition(
    raw: bytes,
    value: dict,
    envelope: dict,
    expected_source_sha: str,
) -> None:
    if (
        frozenset(value) != TRANSITION_KEYS
        or value["schema"] != TRANSITION_SCHEMA
    ):
        raise AssertionError("unexpected transition schema/fields")
    if (
        value["sequence"] != 1
        or value["scope"] != MATERIAL_PAYLOAD_TYPE
    ):
        raise AssertionError("unexpected transition sequence/scope")
    if (
        value["from_key_id"] != OLD_KEY_ID
        or value["from_public_key"] != OLD_PUBLIC_KEY.hex()
    ):
        raise AssertionError("transition old root mismatch")
    if (
        value["to_key_id"] != NEW_KEY_ID
        or value["to_public_key"] != NEW_PUBLIC_KEY.hex()
    ):
        raise AssertionError("transition successor mismatch")
    if (
        value["activation_source_commit"] != expected_source_sha
        or not lower_hex(expected_source_sha, 40)
    ):
        raise AssertionError("transition activation source mismatch")
    if value["production"] is not False:
        raise AssertionError("transition must remain TEST-ONLY/non-production")
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected transition-envelope fields")
    if (
        envelope["schema"] != TRANSITION_ENVELOPE_SCHEMA
        or envelope["algorithm"] != ALGORITHM
        or envelope["key_id"] != OLD_KEY_ID
        or envelope["payload_type"] != TRANSITION_PAYLOAD_TYPE
    ):
        raise AssertionError("unexpected transition-envelope policy")
    if envelope["payload_sha256"] != hashlib.sha256(raw).hexdigest():
        raise AssertionError("transition payload SHA-256 mismatch")
    ed25519_verify(
        OLD_PUBLIC_KEY,
        decode_signature(envelope["signature"]),
        signed_message(raw),
    )


def derive_next(
    current_raw: bytes,
    current: dict,
    transition_raw: bytes,
    transition: dict,
    envelope: dict,
    expected_source_sha: str,
) -> dict:
    validate_state(
        current,
        expected_source_sha if current.get("sequence") == 1 else None,
    )
    validate_transition(
        transition_raw, transition, envelope, expected_source_sha
    )
    if transition["sequence"] != current["sequence"] + 1:
        raise AssertionError("non-monotonic transition/replay rejected")
    if (
        transition["from_key_id"] != current["key_id"]
        or transition["from_public_key"] != current["public_key"]
    ):
        raise AssertionError("transition does not continue current trust state")
    return {
        "schema": STATE_SCHEMA,
        "sequence": transition["sequence"],
        "scope": transition["scope"],
        "key_id": transition["to_key_id"],
        "public_key": transition["to_public_key"],
        "activation_source_commit": transition["activation_source_commit"],
        "predecessor_sha256": hashlib.sha256(current_raw).hexdigest(),
        "transition_sha256": hashlib.sha256(transition_raw).hexdigest(),
        "production": False,
    }


def enforce_floor(value: dict, expected_source_sha: str) -> None:
    validate_state(
        value,
        expected_source_sha if value.get("sequence") == 1 else None,
    )
    if value["sequence"] < MINIMUM_SEQUENCE:
        raise AssertionError(
            f"stale trust state below minimum sequence {MINIMUM_SEQUENCE}"
        )
    if (
        value["sequence"] != 1
        or value["key_id"] != NEW_KEY_ID
        or value["public_key"] != NEW_PUBLIC_KEY.hex()
    ):
        raise AssertionError("unexpected current trust root at rollback floor")


def verify_chain(
    genesis_path: Path,
    transition_path: Path,
    envelope_path: Path,
    final_path: Path,
    expected_source_sha: str,
) -> None:
    rfc8032_selftest()
    genesis_raw, genesis = load_canonical(
        genesis_path, "genesis trust state"
    )
    transition_raw, transition = load_canonical(
        transition_path, "trust transition"
    )
    _, envelope = load_canonical(
        envelope_path, "trust transition envelope"
    )
    final_raw, final = load_canonical(final_path, "final trust state")
    expected = derive_next(
        genesis_raw,
        genesis,
        transition_raw,
        transition,
        envelope,
        expected_source_sha,
    )
    if final_raw != canonical(expected) or final != expected:
        raise AssertionError(
            "final trust state does not match authorized chain"
        )
    enforce_floor(final, expected_source_sha)
    print(
        "RUST-030 stdlib-only monotonic trust chain: "
        f"GREEN sequence={final['sequence']} "
        f"key={final['key_id']} floor={MINIMUM_SEQUENCE}"
    )


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (
        AssertionError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def selftest(
    genesis_path: Path,
    transition_path: Path,
    envelope_path: Path,
    final_path: Path,
    expected_source_sha: str,
) -> None:
    verify_chain(
        genesis_path,
        transition_path,
        envelope_path,
        final_path,
        expected_source_sha,
    )
    genesis_raw, genesis = load_canonical(
        genesis_path, "genesis trust state"
    )
    transition_raw, transition = load_canonical(
        transition_path, "trust transition"
    )
    _, envelope = load_canonical(
        envelope_path, "trust transition envelope"
    )
    final_raw, final = load_canonical(final_path, "final trust state")
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(canonical(value))
            return path

        expect_failure(
            "stale-final-state",
            lambda: enforce_floor(genesis, expected_source_sha),
        )
        cases += 1

        expect_failure(
            "transition-replay",
            lambda: derive_next(
                final_raw,
                final,
                transition_raw,
                transition,
                envelope,
                expected_source_sha,
            ),
        )
        cases += 1

        value = copy.deepcopy(final)
        value["predecessor_sha256"] = "0" * 64
        bad = write_obj("bad-predecessor.json", value)
        expect_failure(
            "predecessor-digest",
            lambda: verify_chain(
                genesis_path,
                transition_path,
                envelope_path,
                bad,
                expected_source_sha,
            ),
        )
        cases += 1

        value = copy.deepcopy(final)
        value["transition_sha256"] = "0" * 64
        bad = write_obj("bad-transition-digest.json", value)
        expect_failure(
            "transition-digest",
            lambda: verify_chain(
                genesis_path,
                transition_path,
                envelope_path,
                bad,
                expected_source_sha,
            ),
        )
        cases += 1

        value = copy.deepcopy(final)
        value["key_id"] = OLD_KEY_ID
        value["public_key"] = OLD_PUBLIC_KEY.hex()
        bad = write_obj("downgrade-key.json", value)
        expect_failure(
            "current-key-downgrade",
            lambda: verify_chain(
                genesis_path,
                transition_path,
                envelope_path,
                bad,
                expected_source_sha,
            ),
        )
        cases += 1

        value = copy.deepcopy(transition)
        value["from_key_id"] = "unknown-old-key"
        bad = write_obj("bad-from-key.json", value)
        expect_failure(
            "transition-from-key",
            lambda: verify_chain(
                genesis_path,
                bad,
                envelope_path,
                final_path,
                expected_source_sha,
            ),
        )
        cases += 1

        value = copy.deepcopy(transition)
        value["to_public_key"] = "0" * 64
        bad = write_obj("bad-successor.json", value)
        expect_failure(
            "transition-successor",
            lambda: verify_chain(
                genesis_path,
                bad,
                envelope_path,
                final_path,
                expected_source_sha,
            ),
        )
        cases += 1

        value = copy.deepcopy(envelope)
        sig = bytearray(decode_signature(value["signature"]))
        sig[0] ^= 1
        value["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad = write_obj("bad-signature.json", value)
        expect_failure(
            "transition-signature",
            lambda: verify_chain(
                genesis_path,
                transition_path,
                bad,
                final_path,
                expected_source_sha,
            ),
        )
        cases += 1

        expect_failure(
            "activation-source",
            lambda: verify_chain(
                genesis_path,
                transition_path,
                envelope_path,
                final_path,
                "0" * 40,
            ),
        )
        cases += 1

        noncanonical = root / "noncanonical-state.json"
        noncanonical.write_text(
            json.dumps(final, indent=2) + "\n", encoding="utf-8"
        )
        expect_failure(
            "noncanonical-state",
            lambda: verify_chain(
                genesis_path,
                transition_path,
                envelope_path,
                noncanonical,
                expected_source_sha,
            ),
        )
        cases += 1

    if cases != 10:
        raise AssertionError(
            f"unexpected RUST-030 selftest count: {cases}"
        )
    print(
        "RUST-030 stdlib-only monotonic trust fail-closed contract: "
        "10/10 expected cases passed"
    )


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(
            "usage: rust_030_stdlib_monotonic_trust_verify.py "
            "rfc-selftest|verify|selftest ..."
        )
    cmd = sys.argv[1]
    if cmd == "rfc-selftest" and len(sys.argv) == 2:
        rfc8032_selftest()
    elif cmd in {"verify", "selftest"} and len(sys.argv) == 7:
        fn = verify_chain if cmd == "verify" else selftest
        fn(
            Path(sys.argv[2]),
            Path(sys.argv[3]),
            Path(sys.argv[4]),
            Path(sys.argv[5]),
            sys.argv[6],
        )
    else:
        raise SystemExit("invalid RUST-030 command/arguments")


if __name__ == "__main__":
    main()
