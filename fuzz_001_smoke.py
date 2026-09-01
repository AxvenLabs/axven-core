#!/usr/bin/env python3
"""FUZZ-001 bounded deterministic smoke over Axven hostile-input surfaces."""
from __future__ import annotations

import hashlib
import random
import socket
import struct

import axven
import p2p
import rpc
import wallet

MAX_FUZZ_INPUT_BYTES = 4096
MUTATION_CASES = 768


def _repeat_to_size(data: bytes, size: int) -> bytes:
    if not data:
        return b"\x00" * size
    copies = (size + len(data) - 1) // len(data)
    return (data * copies)[:size]


def _exercise_p2p_frame(raw: bytes) -> None:
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(struct.pack(">I", len(raw)) + raw)
        try:
            p2p.recv_message(receiver)
        except p2p.ProtocolError:
            # Rejection is the expected outcome for most fuzz-generated frames.
            pass
    finally:
        sender.close()
        receiver.close()


def exercise_one(data: bytes) -> None:
    """Exercise one bounded fuzz input; unexpected exceptions are test failures."""
    if type(data) is not bytes:
        raise TypeError("fuzz input must be bytes")
    data = data[:MAX_FUZZ_INPUT_BYTES]
    if not data:
        data = b"\x00"

    selector = data[0] % 5
    payload = data[1:]

    if selector == 0:
        try:
            p2p._preflight_json_nesting(payload)
        except p2p.ProtocolError:
            pass
        return

    if selector == 1:
        try:
            rpc._preflight_json_nesting(payload)
        except rpc.RPCError:
            pass
        return

    if selector == 2:
        try:
            wallet._preflight_backup_json_nesting(payload)
        except wallet.BackupError:
            pass
        return

    if selector == 3:
        _exercise_p2p_frame(payload)
        return

    # Exercise the production pyca/OpenSSL ML-DSA verifier with attacker-like
    # full-size public-key/signature bytes. The wrapper must fail closed and
    # never leak backend parser exceptions through the consensus-facing API.
    public_key = _repeat_to_size(payload[:1536], 1312)
    signature_material = payload[1536:] if len(payload) > 1536 else payload
    signature = _repeat_to_size(signature_material, 2420)
    message = hashlib.sha256(payload).digest()
    result = axven._verify_mldsa44_signature(public_key, message, signature)
    if type(result) is not bool:
        raise AssertionError("ML-DSA verifier must return bool")


def _mutate(rng: random.Random, seed: bytes) -> bytes:
    buf = bytearray(seed[:MAX_FUZZ_INPUT_BYTES])
    operations = 1 + rng.randrange(8)
    for _ in range(operations):
        action = rng.randrange(5)
        if action == 0 and buf:
            at = rng.randrange(len(buf))
            buf[at] ^= 1 << rng.randrange(8)
        elif action == 1 and len(buf) < MAX_FUZZ_INPUT_BYTES:
            at = rng.randrange(len(buf) + 1)
            room = min(32, MAX_FUZZ_INPUT_BYTES - len(buf))
            chunk = bytes(rng.randrange(256) for _ in range(1 + rng.randrange(room)))
            buf[at:at] = chunk
        elif action == 2 and buf:
            at = rng.randrange(len(buf))
            end = min(len(buf), at + 1 + rng.randrange(min(32, len(buf) - at)))
            del buf[at:end]
        elif action == 3 and buf:
            at = rng.randrange(len(buf))
            end = min(len(buf), at + 1 + rng.randrange(min(32, len(buf) - at)))
            buf[at:end] = reversed(buf[at:end])
        else:
            if len(buf) < MAX_FUZZ_INPUT_BYTES:
                buf.extend(bytes([rng.randrange(256)]))
    return bytes(buf[:MAX_FUZZ_INPUT_BYTES])


def main() -> None:
    corpus = [
        b"",
        b'{}',
        b'{"type":"get_status"}',
        b'{"type":"status","type":"get_status"}',
        b'{"method":"get_status","params":{}}',
        b'{"version":1,"cipher":"aes-256-gcm"}',
        b'{"x":' + b'[' * 40 + b'0' + b']' * 40 + b'}',
        b'{"x":"[{,}]\\\"\\\\"}',
        b'{"x":] ',
        b"\xff\xfe\xfd\x00{}",
        b"[" + b"0," * 512 + b"0]",
    ]

    # Guarantee every surface receives every seed before mutation begins.
    executed = 0
    for selector in range(5):
        for seed in corpus:
            exercise_one(bytes([selector]) + seed)
            executed += 1

    rng = random.Random(0xA7_01_F0_01)
    for _ in range(MUTATION_CASES):
        seed = bytes([rng.randrange(5)]) + rng.choice(corpus)
        exercise_one(_mutate(rng, seed))
        executed += 1

    print(
        "FUZZ-001 deterministic smoke: "
        f"{executed} bounded hostile-input cases GREEN"
    )


if __name__ == "__main__":
    main()
