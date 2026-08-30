#!/usr/bin/env python3
"""SEC-189: canonical P2P transaction/coinbase wire representation."""
from __future__ import annotations

from p2p_tx_bounds import validate_tx_string_bounds

NULL_TXID = "0" * 64
COINBASE_INDEX = 0xFFFFFFFF


def expect_reject(name, tx):
    try:
        validate_tx_string_bounds(tx)
    except ValueError:
        print(f"[GREEN] {name}")
        return
    raise AssertionError(name)


def main():
    checks = 0

    coinbase = {
        "inputs": [{"prev_txid": NULL_TXID, "index": COINBASE_INDEX}],
        "outputs": [{"amount": 1, "recipient": "M" + "0" * 40}],
        "coinbase_height": 1,
    }
    validate_tx_string_bounds(coinbase)
    print("[GREEN] canonical coinbase wire accepted")
    checks += 1

    witness_coinbase = {
        **coinbase,
        "inputs": [{
            "prev_txid": NULL_TXID,
            "index": COINBASE_INDEX,
            "signature": "AAAA",
            "public_key": "AAAA",
        }],
    }
    expect_reject("coinbase witness aliases rejected", witness_coinbase)
    checks += 1

    regular = {
        "inputs": [{
            "prev_txid": "1" * 64,
            "index": 0,
            "scheme": "ml-dsa-44",
            "signature": "AAAA",
            "public_key": "AAAA",
        }],
        "outputs": [{"amount": 1, "recipient": "M" + "0" * 40}],
    }
    validate_tx_string_bounds(regular)
    print("[GREEN] canonical regular transaction wire accepted")
    checks += 1

    regular_with_coinbase_height = {**regular, "coinbase_height": 7}
    expect_reject(
        "coinbase_height semantic alias rejected on regular transaction",
        regular_with_coinbase_height,
    )
    checks += 1

    missing_auth = {
        **regular,
        "inputs": [{
            "prev_txid": "1" * 64,
            "index": 0,
            "scheme": "ml-dsa-44",
            "public_key": "AAAA",
        }],
    }
    expect_reject("incomplete regular input field set rejected", missing_auth)
    checks += 1

    output_alias = {
        **regular,
        "outputs": [{
            "amount": 1,
            "recipient": "M" + "0" * 40,
            "memo": "ignored-by-consensus",
        }],
    }
    expect_reject("unknown transaction output fields rejected", output_alias)
    checks += 1

    top_level_alias = {**regular, "memo": "ignored"}
    expect_reject("unknown transaction top-level fields rejected", top_level_alias)
    checks += 1

    print(f"SEC-189 P2P coinbase canonicality: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
