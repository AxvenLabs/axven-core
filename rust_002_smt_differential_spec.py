#!/usr/bin/env python3
"""RUST-002: test-only Rust SMT mirror must equal the Python consensus oracle."""
from __future__ import annotations

import hashlib
import inspect
import random

import axven
import axven_native


def as_entries(utxo):
    return [
        (
            op,
            value["amount"],
            value["recipient"],
            value["coinbase"],
            value["height"],
        )
        for op, value in utxo.items()
    ]


def assert_equal_root(utxo):
    python_root = axven.smt_root_reference(utxo)
    rust_root = axven_native.smt_root_mirror(as_entries(utxo))
    assert rust_root == python_root, (rust_root, python_root, len(utxo))
    return python_root


def make_value(rng, index):
    scheme = "NMH"[index % 3]
    recipient = scheme + f"{rng.getrandbits(160):040x}"
    return {
        "amount": rng.randrange(1, axven.MAX_SUPPLY + 1),
        "recipient": recipient,
        "coinbase": bool(rng.getrandbits(1)),
        "height": rng.randrange(0, 25_001),
    }


def make_outpoint(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest() + ":0"


def main():
    checks = 0

    assert axven_native.smt_root_mirror([]) == axven.SMT_EMPTY_ROOT
    checks += 1
    print("[GREEN] empty Rust SMT root equals the Python canonical empty root")

    fixed = {
        make_outpoint("alpha"): {
            "amount": 1,
            "recipient": "N" + "1" * 40,
            "coinbase": False,
            "height": 0,
        },
        make_outpoint("beta"): {
            "amount": 50 * axven.COIN,
            "recipient": "M" + "2" * 40,
            "coinbase": True,
            "height": 1,
        },
        make_outpoint("gamma"): {
            "amount": axven.MAX_SUPPLY,
            "recipient": "H" + "3" * 40,
            "coinbase": False,
            "height": 10_000,
        },
    }
    expected = assert_equal_root(fixed)
    reversed_entries = list(reversed(as_entries(fixed)))
    assert axven_native.smt_root_mirror(reversed_entries) == expected
    checks += 1
    print("[GREEN] fixed vectors and input-order changes are byte-for-byte identical")

    rng = random.Random(0xA7_02_2026)
    for case in range(200):
        utxo = {}
        for index in range(rng.randrange(0, 65)):
            op = make_outpoint(f"random-{case}-{index}-{rng.getrandbits(64)}")
            utxo[op] = make_value(rng, index)
        expected = assert_equal_root(utxo)
        shuffled = as_entries(utxo)
        rng.shuffle(shuffled)
        assert axven_native.smt_root_mirror(shuffled) == expected
    checks += 1
    print("[GREEN] 200 deterministic randomized state fixtures match the Python oracle")

    state = {}
    known = []
    for step in range(120):
        if known and rng.random() < 0.35:
            victim = known.pop(rng.randrange(len(known)))
            state.pop(victim)
        else:
            op = make_outpoint(f"mutation-{step}-{rng.getrandbits(128)}")
            if op not in state:
                known.append(op)
            state[op] = make_value(rng, step)
        assert_equal_root(state)
    checks += 1
    print("[GREEN] insert/update/delete mutation sequences remain differential-identical")

    stable_entries = as_entries(fixed)
    roots = {axven_native.smt_root_mirror(stable_entries) for _ in range(20)}
    assert roots == {expected if fixed == state else axven.smt_root_reference(fixed)}
    checks += 1
    print("[GREEN] repeated native replay is deterministic")

    duplicate = stable_entries + [stable_entries[0]]
    try:
        axven_native.smt_root_mirror(duplicate)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate UTXO outpoint accepted")

    bad_negative = list(stable_entries)
    op, _, recipient, coinbase, height = bad_negative[0]
    bad_negative[0] = (op, -1, recipient, coinbase, height)
    try:
        axven_native.smt_root_mirror(bad_negative)
    except OverflowError:
        pass
    else:
        raise AssertionError("negative amount crossed u64 FFI boundary")
    checks += 1
    print("[GREEN] duplicate state and non-canonical integer domains fail closed at the FFI boundary")

    expected_source = inspect.getsource(axven.expected_state_root)
    assert "smt_root_reference" in expected_source
    assert "axven_native" not in expected_source
    for production_name in ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py"):
        with open(production_name, "r", encoding="utf-8") as handle:
            assert "axven_native" not in handle.read(), production_name
    checks += 1
    print("[GREEN] production consensus and service paths remain Python-only")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] RUST-002 leaves canonical chain and PQ activation identity unchanged")

    assert checks == 8, checks
    print("RUST-002 SMT differential mirror: 8/8 GREEN")


if __name__ == "__main__":
    main()
