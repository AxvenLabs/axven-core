#!/usr/bin/env python3
"""SEC-136 bounds confirmed-transaction lookup work on the active chain."""

import inspect
import threading

import axven
import core as core_module


class FakeBlock:
    def __init__(self,height,transactions,hash_value):
        self.height=height
        self.transactions=list(transactions)
        self._hash=hash_value

    def hash(self):
        return self._hash


class FakeChain:
    def __init__(self,blocks):
        self.blocks=list(blocks)
        self._state_lock=threading.RLock()


class FakeMempool:
    def __init__(self):
        self.txs={}
        self._lock=threading.RLock()


def make_tx(seed):
    return axven.Transaction(
        [],
        [axven.TxOutput(seed+1,"N"+("1"*40))],
        coinbase_height=seed,
    )


def main():
    checks=[]

    def green(name,condition):
        assert condition,name
        checks.append(name)
        print("[GREEN]",name)

    tx0=make_tx(10)
    tx1=make_tx(11)
    tx2=make_tx(12)
    tx3=make_tx(13)
    tx4=make_tx(14)
    tx_alt=make_tx(15)
    ids=[tx.txid() for tx in (tx0,tx1,tx2,tx3,tx4,tx_alt)]

    b0=FakeBlock(0,[tx0.to_dict()],"0"*64)
    b1=FakeBlock(1,[tx1.to_dict(),tx2.to_dict()],"1"*64)
    b2=FakeBlock(2,[tx3.to_dict(),tx4.to_dict()],"2"*64)
    b2_alt=FakeBlock(2,[tx_alt.to_dict()],"3"*64)

    service=object.__new__(core_module.AxvenCore)
    service.chain=FakeChain([b0,b1])
    service.mempool=FakeMempool()

    original_txid=axven.Transaction.txid
    calls={"count":0}

    def counted_txid(self):
        calls["count"]+=1
        return original_txid(self)

    axven.Transaction.txid=counted_txid
    try:
        result=service.get_transaction(ids[2])
        green(
            "cold confirmed lookup builds exact active-chain index once",
            result["txid"] == ids[2]
            and result["status"] == "confirmed"
            and result["height"] == 1
            and result["block_hash"] == "1"*64
            and calls["count"] == 3,
        )

        before=calls["count"]
        for _ in range(8):
            try:
                service.get_transaction("f"*64)
            except KeyError:
                pass
            else:
                raise AssertionError("missing transaction unexpectedly resolved")
        green(
            "repeated hot misses do not rescan or rehash historical transactions",
            calls["count"] == before,
        )

        again=service.get_transaction(ids[1])
        green(
            "repeated confirmed hit reuses hot index without historical scan",
            again["height"] == 1 and calls["count"] == before,
        )

        service.chain.blocks.append(b2)
        appended=service.get_transaction(ids[4])
        green(
            "normal active-chain extension indexes only newly appended block",
            appended["height"] == 2
            and appended["block_hash"] == "2"*64
            and calls["count"] == before+2,
        )

        after_append=calls["count"]
        service.chain.blocks=[b0,b1,b2_alt]
        alternate=service.get_transaction(ids[5])
        green(
            "reorg rebuilds index against replacement active chain",
            alternate["height"] == 2
            and alternate["block_hash"] == "3"*64
            and calls["count"] == after_append+4,
        )

        after_reorg=calls["count"]
        try:
            service.get_transaction(ids[4])
        except KeyError:
            stale_rejected=True
        else:
            stale_rejected=False
        green(
            "reorg drops disconnected transaction ids from service index",
            stale_rejected and calls["count"] == after_reorg,
        )
    finally:
        axven.Transaction.txid=original_txid

    lookup_src=inspect.getsource(core_module.AxvenCore._get_transaction_locked)
    refresh_src=inspect.getsource(core_module.AxvenCore._refresh_confirmed_tx_index_locked)
    green(
        "confirmed lookup no longer reverse-scans every active block per request",
        "for block in reversed(self.chain.blocks)" not in lookup_src
        and "_refresh_confirmed_tx_index_locked().get(txid)" in lookup_src,
    )
    green(
        "active-chain index has explicit append and reorg invalidation paths",
        "start=cached_height+1" in refresh_src
        and "index={}" in refresh_src
        and "cached_tip == blocks[cached_height].hash()" in refresh_src,
    )
    green(
        "confirmed lookup hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-136 confirmed tx lookup work: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
