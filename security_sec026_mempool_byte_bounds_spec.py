#!/usr/bin/env python3
"""SEC-026 bounded mempool byte-budget regression contract."""

import json
import axven


EXPECTED_MAX_MEMPOOL_BYTES = 64 * 1024 * 1024
PAYLOAD_BYTES = 1024 * 1024


def tx_size(tx):
    return len(
        json.dumps(
            tx.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def retained_bytes(mempool):
    return sum(tx_size(tx) for tx in mempool.txs.values())


def main():
    wallet = axven.Wallet()
    chain = axven.Blockchain()

    # Produce enough independent mature UTXOs to create many valid
    # unconfirmed transactions simultaneously.
    for _ in range(axven.COINBASE_MATURITY + 80):
        chain.mine(wallet.address)

    spendable = chain.spendable(wallet.address)
    assert len(spendable) >= 70

    mempool = axven.Mempool(chain)

    # Current address parsing accepts any N-prefixed string. SEC-026 does
    # not change that consensus behavior; it limits node-local mempool RAM.
    large_recipient = wallet.address + ("X" * PAYLOAD_BYTES)

    rejected = False

    for txid, idx, amount in spendable[:70]:
        unsigned = axven.Transaction(
            [axven.TxInput(txid, idx)],
            [axven.TxOutput(amount - 1000, large_recipient)],
        )

        signed = axven.Transaction(
            [wallet.sign_input(unsigned, 0)],
            unsigned.outputs,
        )

        try:
            mempool.add(signed)
        except ValueError as exc:
            if "mempool" not in str(exc).lower():
                raise
            rejected = True
            break

    total = retained_bytes(mempool)

    assert rejected, (
        f"mempool byte budget unbounded: retained "
        f"{total} bytes without rejection"
    )

    assert total <= EXPECTED_MAX_MEMPOOL_BYTES, (
        f"mempool retained {total} bytes, "
        f"expected <= {EXPECTED_MAX_MEMPOOL_BYTES}"
    )

    print(
        f"[GREEN] mempool serialized bytes bounded at "
        f"{total}/{EXPECTED_MAX_MEMPOOL_BYTES}"
    )

    # Existing entry-count policy must remain intact.
    assert len(mempool.txs) <= axven.MAX_MEMPOOL_TXS
    print("[GREEN] transaction-count bound remains intact")

    # Removing one retained transaction must release exactly its byte budget.
    remove_tid = next(iter(mempool.txs))
    remove_size = mempool.tx_sizes[remove_tid]
    bytes_before_remove = mempool.total_bytes

    mempool.remove(remove_tid)

    assert mempool.total_bytes == bytes_before_remove - remove_size
    assert remove_tid not in mempool.tx_sizes
    print("[GREEN] removal releases serialized byte budget")

    # Re-evaluation must rebuild byte accounting from retained transactions.
    expected_bytes = sum(
        axven.serialized_transaction_size(tx)
        for tx in mempool.txs.values()
    )

    chain._reevaluate_mempool()

    rebuilt_bytes = sum(
        axven.serialized_transaction_size(tx)
        for tx in mempool.txs.values()
    )

    assert mempool.total_bytes == rebuilt_bytes
    assert mempool.total_bytes == expected_bytes
    assert set(mempool.tx_sizes) == set(mempool.txs)
    assert sum(mempool.tx_sizes.values()) == mempool.total_bytes

    print("[GREEN] mempool re-evaluation rebuilds byte accounting")
    print("SEC-026 bounded mempool byte budget: 4/4 GREEN")


if __name__ == "__main__":
    main()
