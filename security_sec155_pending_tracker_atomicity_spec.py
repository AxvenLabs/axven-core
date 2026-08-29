#!/usr/bin/env python3
"""SEC-155 pending tracker concurrency and admission publication contract."""

import inspect
import threading
import time
from types import SimpleNamespace

import axven
import core as core_module
import wallet


class FakeTx:
    def __init__(self):
        self.inputs=[axven.TxInput("1" * 64,0)]
        self.outputs=[axven.TxOutput(1,"N" + ("0" * 40))]
    def _in(self):
        return list(self.inputs)
    def to_dict(self):
        return {"inputs":[],"outputs":[]}


class FakeChain:
    def __init__(self):
        self._state_lock=threading.RLock()
        self.tip=SimpleNamespace(height=0)


class FakeMempool:
    def __init__(self, admitted, reconcile_started):
        self._lock=threading.RLock()
        self.txs={}
        self.admitted=admitted
        self.reconcile_started=reconcile_started
    def add(self, tx):
        with self._lock:
            txid="a" * 64
            self.txs[txid]=tx
            self.admitted.set()
            assert self.reconcile_started.wait(2), "reconcile thread did not start"
            return txid


class ProbePending(wallet.PendingTracker):
    def __init__(self, reconcile_started, reconcile_done):
        super().__init__()
        self.reconcile_started=reconcile_started
        self.reconcile_done=reconcile_done
        self.atomic_observed=False
    def reserve(self, txid, outpoints):
        if txid == "a" * 64:
            assert self.reconcile_started.wait(2)
            # Give reconcile a scheduling window.  It must still be blocked on
            # the mempool lock until this reservation has been published.
            time.sleep(0.05)
            assert not self.reconcile_done.is_set(), (
                "reconcile crossed admitted->reserved publication window"
            )
            self.atomic_observed=True
        return super().reserve(txid,outpoints)


def main():
    checks=0

    tracker=wallet.PendingTracker()
    assert hasattr(tracker,"_lock")
    checks+=1
    print("[GREEN] pending tracker owns an internal lock")

    op=("f" * 64,1)
    tracker.reserve("tx-1",[op])
    tracker.reserve("tx-2",[op])
    tracker.release("tx-1")
    assert tracker.is_reserved(op)
    tracker.release("tx-2")
    assert not tracker.is_reserved(op)
    checks+=1
    print("[GREEN] overlapping reservation semantics preserved under lock")

    errors=[]
    stress=wallet.PendingTracker()
    def worker(n):
        try:
            for i in range(200):
                tid=f"{n}-{i}"
                shared=("e" * 64,i % 4)
                stress.reserve(tid,[shared])
                stress.is_reserved(shared)
                stress.release(tid)
        except Exception as exc:
            errors.append(exc)
    threads=[threading.Thread(target=worker,args=(n,)) for n in range(8)]
    for t in threads:t.start()
    for t in threads:t.join(5)
    assert all(not t.is_alive() for t in threads)
    assert not errors,errors
    checks+=1
    print("[GREEN] concurrent reserve/release/read operations complete without tracker races")

    admitted=threading.Event()
    reconcile_started=threading.Event()
    reconcile_done=threading.Event()
    fake_pool=FakeMempool(admitted,reconcile_started)
    fake_chain=FakeChain()
    pending=ProbePending(reconcile_started,reconcile_done)
    service=core_module.AxvenCore.__new__(core_module.AxvenCore)
    service.chain=fake_chain
    service.mempool=fake_pool
    service.identity=object()
    service.pending=pending
    service._propagate_tx_outbound=lambda tx: None

    original_build=core_module.wallet.build_transaction
    original_sign=core_module.wallet.sign_transaction
    fake_tx=FakeTx()
    core_module.wallet.build_transaction=lambda *args,**kwargs: fake_tx
    core_module.wallet.sign_transaction=lambda *args,**kwargs: fake_tx
    send_result=[]
    send_error=[]
    def do_send():
        try:
            send_result.append(service.send(
                axven.SCHEME_ED25519,"N" + ("0" * 40),1,0
            ))
        except Exception as exc:
            send_error.append(exc)
    def do_reconcile():
        assert admitted.wait(2)
        reconcile_started.set()
        pending.reconcile(fake_pool)
        reconcile_done.set()
    try:
        ts=threading.Thread(target=do_send)
        tr=threading.Thread(target=do_reconcile)
        ts.start(); tr.start()
        ts.join(5); tr.join(5)
    finally:
        core_module.wallet.build_transaction=original_build
        core_module.wallet.sign_transaction=original_sign
    assert not ts.is_alive() and not tr.is_alive()
    assert not send_error,send_error
    assert pending.atomic_observed
    assert reconcile_done.is_set()
    assert send_result and send_result[0]["txid"] == "a" * 64
    assert pending.is_reserved(("1" * 64,0))
    checks+=1
    print("[GREEN] reconcile cannot cross admitted-to-reserved publication window")

    with fake_pool._lock:
        fake_pool.txs.clear()
    pending.reconcile(fake_pool)
    assert not pending.is_reserved(("1" * 64,0))
    checks+=1
    print("[GREEN] later reconcile releases reservation after mempool removal")

    tracker_src=inspect.getsource(wallet.PendingTracker)
    assert "self._lock = threading.RLock()" in tracker_src
    assert "with mempool_lock:" in tracker_src
    assert "with self._lock:" in tracker_src
    checks+=1
    print("[GREEN] production tracker serializes state and mempool reconciliation")

    send_src=inspect.getsource(core_module.AxvenCore.send)
    assert send_src.index("with self.chain._state_lock") < send_src.index("with _mempool_guard(self.mempool)")
    assert send_src.index("with _mempool_guard(self.mempool)") < send_src.index("self.mempool.add(signed)")
    assert send_src.index("self.mempool.add(signed)") < send_src.index("self.pending.reserve(txid, ops)")
    assert send_src.index("self.pending.reserve(txid, ops)") < send_src.index("self._propagate_tx_outbound(signed)")
    checks+=1
    print("[GREEN] production send uses chain->mempool->pending publication order")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks+=1
    print("[GREEN] pending atomicity hardening leaves canonical chain identity unchanged")

    assert checks==8,checks
    print("SEC-155 pending tracker atomicity: 8/8 GREEN")


if __name__=="__main__":
    main()
