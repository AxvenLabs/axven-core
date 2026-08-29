#!/usr/bin/env python3
"""SEC-157 atomic persisted chain snapshot contract."""

import json
import tempfile
import threading
import time

import axven


class BlockingBlock:
    def __init__(self, height, entered=None, release=None):
        self.height=height
        self.entered=entered
        self.release=release

    def to_dict(self):
        if self.entered is not None:
            self.entered.set()
            if not self.release.wait(2.0):
                raise AssertionError("snapshot serialization release timed out")
        return {"height":self.height}


class FakeChain:
    def __init__(self, blocks):
        self._state_lock=threading.RLock()
        self.blocks=list(blocks)


def main():
    checks=0
    entered=threading.Event()
    release=threading.Event()
    mutated=threading.Event()
    fake=FakeChain([BlockingBlock(1,entered,release)])

    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td)
        errors=[]

        def persist_worker():
            try:
                store.persist(fake)
            except Exception as exc:
                errors.append(exc)

        writer=threading.Thread(target=persist_worker)
        writer.start()
        assert entered.wait(1.0),"persist never reached block serialization"

        def mutate_worker():
            with fake._state_lock:
                fake.blocks.append(BlockingBlock(2))
                mutated.set()

        mutator=threading.Thread(target=mutate_worker)
        mutator.start()
        time.sleep(0.10)
        assert not mutated.is_set(),(
            "chain mutation entered while persisted snapshot was serializing"
        )
        checks+=1
        print("[GREEN] concurrent chain mutation blocked during snapshot serialization")

        release.set()
        writer.join(2.0); mutator.join(2.0)
        assert not writer.is_alive() and not mutator.is_alive()
        assert not errors,errors
        assert mutated.is_set() and len(fake.blocks)==2
        checks+=1
        print("[GREEN] mutation proceeds after snapshot lock is released")

        payload=json.loads(store.path.read_text(encoding="utf-8"))
        assert payload["blocks"]==[{"height":1}],payload
        checks+=1
        print("[GREEN] persisted file contains one coherent pre-mutation snapshot")

        # File-system work must not inherit the chain-state lock.  A second
        # thread can acquire the lock after snapshot materialization while the
        # already-copied payload is being written.
        acquired=threading.Event()
        original_dumps=axven.json.dumps
        gate_started=threading.Event()
        gate_release=threading.Event()

        def gated_dumps(*args,**kwargs):
            gate_started.set()
            if not gate_release.wait(2.0):
                raise AssertionError("JSON gate timed out")
            return original_dumps(*args,**kwargs)

        axven.json.dumps=gated_dumps
        try:
            second_errors=[]
            writer2=threading.Thread(target=lambda: (
                store.persist(fake)
            ))
            writer2.start()
            assert gate_started.wait(1.0),"persist never reached JSON encoding"

            def acquire_during_io():
                with fake._state_lock:
                    acquired.set()

            probe=threading.Thread(target=acquire_during_io)
            probe.start()
            assert acquired.wait(1.0),"chain lock held across JSON/filesystem work"
            gate_release.set()
            writer2.join(2.0); probe.join(2.0)
            assert not writer2.is_alive() and not probe.is_alive()
        finally:
            axven.json.dumps=original_dumps
            gate_release.set()
        checks+=1
        print("[GREEN] chain lock released before JSON/filesystem persistence work")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks+=1
    print("[GREEN] canonical chain identity unchanged")

    assert checks==5,checks
    print("SEC-157 atomic chain persistence snapshot: 5/5 GREEN")


if __name__=="__main__":
    main()
