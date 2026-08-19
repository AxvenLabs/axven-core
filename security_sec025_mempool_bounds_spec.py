#!/usr/bin/env python3
"""SEC-025 bounded mempool admission regression contract."""

import axven


EXPECTED_MAX_MEMPOOL_TXS = 4096


def make_valid_tx(chain, wallet):
    txid, idx, amount = chain.spendable(wallet.address)[0]

    tx = axven.Transaction(
        [axven.TxInput(txid, idx)],
        [axven.TxOutput(amount - 1000, wallet.address)],
    )

    return axven.Transaction(
        [wallet.sign_input(tx, 0)],
        tx.outputs,
    )


def main():
    wallet = axven.Wallet()
    chain = axven.Blockchain()

    for _ in range(axven.COINBASE_MATURITY + 2):
        chain.mine(wallet.address)

    # Normal admission must remain valid below the cap.
    normal_mp = axven.Mempool(chain)
    normal_tx = make_valid_tx(chain, wallet)
    tid = normal_mp.add(normal_tx)

    assert tid in normal_mp.txs
    print("[GREEN] normal mempool admission preserved")

    normal_mp.remove(tid)

    # Saturate only the accounting table to exercise admission policy.
    # Dummy entries are sufficient because SEC-025 concerns the boundary
    # before a new validated transaction is retained.
    for i in range(EXPECTED_MAX_MEMPOOL_TXS):
        key = f"sec025-{i}"
        normal_mp.txs[key] = None
        normal_mp.fees[key] = 0

    assert len(normal_mp.txs) == EXPECTED_MAX_MEMPOOL_TXS

    candidate = make_valid_tx(chain, wallet)
    spent_before = set(normal_mp.spent)

    try:
        normal_mp.add(candidate)
    except ValueError as exc:
        assert "mempool" in str(exc).lower()
    else:
        raise AssertionError(
            f"mempool unbounded: accepted "
            f"{len(normal_mp.txs)} entries"
        )

    assert len(normal_mp.txs) == EXPECTED_MAX_MEMPOOL_TXS
    assert normal_mp.spent == spent_before

    print(
        f"[GREEN] mempool bounded at "
        f"{EXPECTED_MAX_MEMPOOL_TXS}"
    )
    print("[GREEN] rejected admission leaves mempool state unchanged")
    print("SEC-025 bounded mempool admission: 3/3 GREEN")


if __name__ == "__main__":
    main()
