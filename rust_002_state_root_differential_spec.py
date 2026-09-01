#!/usr/bin/env python3
"""RUST-002: test-only native Sparse-Merkle root differential contract."""
from __future__ import annotations

import random
from pathlib import Path

import axven
import axven_native

ROOT = Path(__file__).resolve().parent


def _rows(utxo):
    return [
        (
            op,
            int(value["amount"]),
            str(value["recipient"]),
            bool(value["coinbase"]),
            int(value["height"]),
        )
        for op, value in utxo.items()
    ]


def _assert_match(utxo):
    python_root = axven.smt_root_reference(utxo)
    native_root = axven_native.smt_root_mirror(_rows(utxo))
    assert native_root == python_root, (native_root, python_root, len(utxo))
    return native_root


def _random_utxo(rng, case, size):
    utxo = {}
    prefixes = ("N", "M", "H")
    while len(utxo) < size:
        txid = f"{rng.getrandbits(256):064x}"
        index = rng.randrange(4)
        op = f"{txid}:{index}"
        if op in utxo:
            continue
        recipient = prefixes[rng.randrange(len(prefixes))] + f"{rng.getrandbits(160):040x}"
        utxo[op] = {
            "amount": rng.randrange(1, 100 * axven.COIN),
            "recipient": recipient,
            "coinbase": bool(rng.getrandbits(1)),
            "height": rng.randrange(0, 100_000),
        }
    return utxo


def main() -> None:
    checks = 0

    empty_root = _assert_match({})
    assert empty_root == "b178c245c947ea7e21ecede07728941a6ab1b706143c06873baff8ebd6de6308"
    checks += 1
    print("[GREEN] native empty Sparse-Merkle root matches the Python oracle")

    one = {
        "00" * 32 + ":0": {
            "amount": 1,
            "recipient": "N" + "1" * 40,
            "coinbase": False,
            "height": 1,
        }
    }
    assert _assert_match(one) == "f9c17f4ac4ffe9b72aaebc1ed3a4c241f0316c29883a8adcbef610a92170e45d"
    two = dict(one)
    two["11" * 32 + ":1"] = {
        "amount": 5_000_000_000,
        "recipient": "M" + "2" * 40,
        "coinbase": True,
        "height": 100,
    }
    assert _assert_match(two) == "72850532475df352c95089fc89890c848a04612ccc583b9111cd19c15be9d138"
    checks += 1
    print("[GREEN] fixed one/two-leaf vectors match byte-for-byte")

    rng = random.Random(0xA7E2002)
    for case in range(96):
        size = rng.randrange(0, 65)
        _assert_match(_random_utxo(rng, case, size))
    checks += 1
    print("[GREEN] 96 seeded randomized UTXO states match the Python reference")

    state = _random_utxo(rng, 999, 128)
    _assert_match(state)
    for step in range(48):
        if step % 3 == 0 and state:
            op = rng.choice(tuple(state))
            state.pop(op)
        elif step % 3 == 1 and state:
            op = rng.choice(tuple(state))
            updated = dict(state[op])
            updated["amount"] += 1 + (step % 17)
            updated["height"] += 1
            state[op] = updated
        else:
            state.update(_random_utxo(rng, 2_000 + step, 1))
        _assert_match(state)
    checks += 1
    print("[GREEN] insert/update/delete sequence remains differential-exact")

    large = _random_utxo(rng, 3_000, 1_000)
    expected = _assert_match(large)
    rows = _rows(large)
    for _ in range(16):
        rng.shuffle(rows)
        assert axven_native.smt_root_mirror(rows) == expected
    checks += 1
    print("[GREEN] 1,000-entry mirror is deterministic and input-order independent")

    duplicate = rows[0]
    try:
        axven_native.smt_root_mirror([duplicate, duplicate])
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate outpoint must fail closed")
    checks += 1
    print("[GREEN] malformed duplicate FFI records fail closed")

    for name in ("axven.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py", "core.py"):
        production = (ROOT / name).read_text(encoding="utf-8")
        assert "axven_native" not in production, name
    checks += 1
    print("[GREEN] native state-root mirror remains test-only and off the production path")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] RUST-002 leaves chain identity and activation semantics unchanged")

    assert checks == 8, checks
    print("RUST-002 test-only state-root differential: 8/8 GREEN")


if __name__ == "__main__":
    main()
