#!/usr/bin/env python3
"""SEC-090 makes mempool validation/publication atomic across worker threads."""
import threading
import time

import axven
from core import AxvenCore


def signed_spend(wallet, prev_txid, amount_in, amount_out):
    base=axven.Transaction(
        [axven.TxInput(prev_txid,0)],
        [axven.TxOutput(amount_out,wallet.address)],
    )
    return axven.Transaction([wallet.sign_input(base,0)],base.outputs)


def main():
    checks=[]
    def ok(name,condition):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    chain=axven.Blockchain()
    mempool=axven.Mempool(chain)
    wallet=axven.Wallet()
    prev_txid="ab"*32
    amount=100_000
    op=axven.outpoint(prev_txid,0)
    chain.utxo[op]={
        "amount":amount,
        "recipient":wallet.address,
        "coinbase":False,
        "height":0,
    }
    tx_a=signed_spend(wallet,prev_txid,amount,90_000)
    tx_b=signed_spend(wallet,prev_txid,amount,80_000)
    assert tx_a.txid()!=tx_b.txid()

    original_verify=axven.verify_input
    first_entered=threading.Event()
    release_first=threading.Event()
    second_entered=threading.Event()
    outcomes={}

    def gated_verify(inp,utxo,sighash,height=0):
        name=threading.current_thread().name
        if name=="sec090-first":
            first_entered.set()
            if not release_first.wait(2.0):
                raise AssertionError("first validator release timeout")
        elif name=="sec090-second":
            second_entered.set()
        return original_verify(inp,utxo,sighash,height)

    def submit(label,tx):
        try:
            outcomes[label]=("ok",mempool.add(tx))
        except Exception as exc:
            outcomes[label]=("err",f"{type(exc).__name__}: {exc}")

    axven.verify_input=gated_verify
    try:
        first=threading.Thread(name="sec090-first",target=submit,args=("first",tx_a))
        second=threading.Thread(name="sec090-second",target=submit,args=("second",tx_b))
        first.start()
        ok("first validation entered",first_entered.wait(1.0))
        second.start()
        leaked=second_entered.wait(0.20)
        ok("second conflicting validation blocked",not leaked)
        release_first.set()
        first.join(2.0); second.join(2.0)
        ok("concurrent submissions terminate",not first.is_alive() and not second.is_alive())
    finally:
        release_first.set()
        axven.verify_input=original_verify

    successes=[label for label,(state,_) in outcomes.items() if state=="ok"]
    failures=[detail for state,detail in outcomes.values() if state=="err"]
    ok("exactly one conflicting transaction accepted",len(successes)==1)
    ok("losing transaction rejected as double spend",len(failures)==1 and "Double spend" in failures[0])
    with mempool._lock:
        ok("mempool conflict accounting consistent",len(mempool.txs)==1 and mempool.spent=={op})
        ok("mempool byte accounting consistent",mempool.total_bytes==sum(mempool.tx_sizes.values()))

    mempool._lock.acquire()
    select_started=threading.Event(); select_done=threading.Event()
    def select_worker():
        select_started.set(); mempool.select(); select_done.set()
    t=threading.Thread(target=select_worker)
    t.start()
    ok("select worker started",select_started.wait(1.0))
    ok("select waits for mempool lock",not select_done.wait(0.15))
    mempool._lock.release()
    t.join(1.0)
    ok("select resumes after lock release",select_done.is_set())

    service=AxvenCore(chain=chain,mempool=mempool)
    mempool._lock.acquire()
    view_started=threading.Event(); view_done=threading.Event()
    def view_worker():
        view_started.set(); service.mempool_view(); view_done.set()
    t=threading.Thread(target=view_worker)
    t.start()
    ok("mempool view worker started",view_started.wait(1.0))
    ok("RPC mempool snapshot waits for lock",not view_done.wait(0.15))
    mempool._lock.release()
    t.join(1.0)
    ok("RPC mempool snapshot resumes",view_done.is_set())

    print(f"SEC-090 atomic mempool state: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
