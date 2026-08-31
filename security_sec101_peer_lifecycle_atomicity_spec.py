#!/usr/bin/env python3
"""SEC-101 outbound peer lifecycle concurrency contract."""

import threading
import time

import p2p
from core import AxvenCore


class FakeTx:
    def to_dict(self):
        return {"inputs": [], "outputs": []}

    def txid(self):
        return "11" * 32


def main():
    checks = 0

    core = AxvenCore()
    entered = threading.Event()
    release = threading.Event()
    overlap = threading.Event()
    counter_lock = threading.Lock()
    active = [0]

    def persist(_peers):
        with counter_lock:
            active[0] += 1
            if active[0] > 1:
                overlap.set()
        entered.set()
        release.wait(1.0)
        with counter_lock:
            active[0] -= 1

    core.peer_persist_callback = persist
    first = ("127.0.0.1", 19101)
    second = ("127.0.0.1", 19102)
    t1 = threading.Thread(target=lambda: core.add_outbound_peer(first), daemon=True)
    t2 = threading.Thread(target=lambda: core.add_outbound_peer(second), daemon=True)
    t1.start()
    assert entered.wait(1.0), "first persistence callback did not start"
    t2.start()
    time.sleep(0.15)
    release.set()
    t1.join(2.0); t2.join(2.0)
    assert not overlap.is_set(), "peer persistence callbacks overlapped"
    assert set(core.outbound_peer_addresses()) == {first, second}
    checks += 1
    print("[GREEN] peer membership persistence serialized")

    core = AxvenCore()
    peer = ("127.0.0.1", 19103)
    core.add_outbound_peer(peer)
    entered = threading.Event(); release = threading.Event()
    original_propagate_tx = p2p.propagate_tx

    def blocked_propagate(_addr, _tx, remote_host_gate=None):
        assert callable(remote_host_gate), "propagation provenance gate missing"
        entered.set()
        release.wait(1.0)
        raise ConnectionRefusedError("late propagation failure")

    p2p.propagate_tx = blocked_propagate
    try:
        worker = threading.Thread(
            target=lambda: core._propagate_tx_outbound(FakeTx()), daemon=True
        )
        worker.start()
        assert entered.wait(1.0), "propagation did not start"
        core.remove_outbound_peer(peer)
        release.set(); worker.join(2.0)
        assert peer not in core.peer_last_error, "removed peer health state recreated"
    finally:
        p2p.propagate_tx = original_propagate_tx
    checks += 1
    print("[GREEN] late propagation cannot recreate removed peer state")

    core = AxvenCore()
    peer = ("127.0.0.1", 19104)
    core.add_outbound_peer(peer)
    entered = threading.Event(); release = threading.Event()
    original_sync = p2p.sync_to_peer

    def blocked_sync(*_args, **_kwargs):
        entered.set()
        release.wait(1.0)
        return 0

    p2p.sync_to_peer = blocked_sync
    try:
        result = []
        worker = threading.Thread(
            target=lambda: result.append(core.sync_outbound_peer(peer)), daemon=True
        )
        worker.start()
        assert entered.wait(1.0), "sync did not start"
        core.remove_outbound_peer(peer)
        release.set(); worker.join(2.0)
        assert result and result[0]["ok"] is True
        assert peer not in core.peer_last_error
        assert peer not in core.peer_sync_successes
        assert peer not in core.peer_health_current_state
    finally:
        p2p.sync_to_peer = original_sync
    checks += 1
    print("[GREEN] late sync cannot recreate removed peer state")

    core = AxvenCore(); peer = ("127.0.0.1", 19105); core.add_outbound_peer(peer)
    snapshot = core.outbound_peer_addresses(); snapshot.clear()
    assert core.outbound_peer_addresses() == [peer]
    checks += 1
    print("[GREEN] outbound peer address snapshots are defensive")

    print(f"SEC-101 peer lifecycle atomicity: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
