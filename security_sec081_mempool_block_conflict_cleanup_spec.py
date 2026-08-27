#!/usr/bin/env python3
# SEC-081 normal-extension mempool conflict cleanup regression contract.

import axven


def signed_spend(wallet, coin, recipient, fee):
    txid, idx, amount = coin
    unsigned = axven.Transaction(
        [axven.TxInput(txid, idx)],
        [axven.TxOutput(amount - fee, recipient)],
    )
    return axven.Transaction(
        [wallet.sign_input(unsigned, 0)],
        unsigned.outputs,
    )


class StaticPool:
    def __init__(self, tx):
        self.tx = tx

    def select(self):
        return [self.tx]


def main():
    miner = axven.Wallet()
    recipient_a = axven.Wallet()
    recipient_b = axven.Wallet()
    chain = axven.Blockchain()

    for _ in range(axven.COINBASE_MATURITY + 4):
        chain.mine(miner.address)

    spendable = chain.spendable(miner.address)
    assert len(spendable) >= 2
    conflict_coin, keep_coin = spendable[:2]

    mempool = axven.Mempool(chain)
    pending_conflict = signed_spend(miner, conflict_coin, recipient_a.address, 1000)
    pending_keep = signed_spend(miner, keep_coin, recipient_a.address, 1100)
    conflict_tid = mempool.add(pending_conflict)
    keep_tid = mempool.add(pending_keep)

    assert conflict_tid in mempool.txs and keep_tid in mempool.txs
    print("[GREEN] independent pending transactions admitted before competing block")

    competing = signed_spend(miner, conflict_coin, recipient_b.address, 2000)
    assert competing.txid() != conflict_tid
    print("[GREEN] competing block transaction has distinct txid for same outpoint")

    block = chain.build_candidate(miner.address, StaticPool(competing))
    ok, status = chain.add_block(block)
    assert ok and status == "extended"
    print("[GREEN] competing transaction accepted through normal chain extension")

    assert conflict_tid not in mempool.txs
    print("[GREEN] stale mempool conflict removed after normal extension")

    assert keep_tid in mempool.txs
    print("[GREEN] unrelated mempool transaction preserved")

    keep_ops = {
        axven.outpoint(i.prev_txid, i.index)
        for i in pending_keep._in()
    }
    assert mempool.spent == keep_ops
    assert mempool.total_bytes == mempool.tx_sizes[keep_tid]
    assert mempool.total_bytes == axven.serialized_transaction_size(pending_keep)
    print("[GREEN] mempool spent and byte accounting remain exact")

    candidate = chain.build_candidate(miner.address, mempool)
    candidate_tids = {tx.txid() for tx in candidate.txs()[1:]}
    assert keep_tid in candidate_tids
    print("[GREEN] subsequent mining candidate builds without stale-input failure")

    chain.mine(miner.address, mempool)
    assert keep_tid not in mempool.txs
    assert mempool.total_bytes == 0
    assert not mempool.spent
    assert chain.validate()
    print("[GREEN] remaining transaction confirms and chain stays valid")

    print("SEC-081 mempool block conflict cleanup: 8/8 GREEN")


if __name__ == "__main__":
    main()
