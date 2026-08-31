#!/usr/bin/env python3
"""SEC-223: outbound TX/block propagation must not serialize peer latency."""

from __future__ import annotations

import threading

import p2p
from core import AxvenCore


class FakeTx:
    def to_dict(self):
        return {"inputs": [], "outputs": []}

    def txid(self):
        return "23" * 32


class FakeBlock:
    def to_dict(self):
        return {"height": 1, "transactions": []}

    def hash(self):
        return "24" * 32


def _exercise(method_name, transport_name, payload, base_port):
    core = AxvenCore()
    peers = [(f"127.0.0.{i + 1}", base_port + i) for i in range(8)]
    for peer in peers:
        core.add_outbound_peer(peer)

    entered_two = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = 0
    peak = 0
    calls = []

    original = getattr(p2p, transport_name)

    def blocked(addr, obj, **kwargs):
        nonlocal active, peak
        gate = kwargs.get("remote_host_gate")
        assert callable(gate), "resolved-peer provenance gate missing"
        assert gate(addr[0]) is True
        with lock:
            calls.append(addr)
            active += 1
            peak = max(peak, active)
            if active >= 2:
                entered_two.set()
        release.wait(2.0)
        with lock:
            active -= 1
        raise ConnectionRefusedError("simulated slow/offline peer")

    setattr(p2p, transport_name, blocked)
    worker = threading.Thread(
        target=lambda: getattr(core, method_name)(payload),
        daemon=True,
    )
    try:
        worker.start()
        # A serial implementation can only enter one transport call and will
        # remain stuck there until release. Hardened propagation must admit at
        # least two independent peer attempts before the first one completes.
        assert entered_two.wait(0.75), (
            f"{transport_name} outbound fanout remains serial"
        )
    finally:
        release.set()
        worker.join(5.0)
        setattr(p2p, transport_name, original)

    assert not worker.is_alive(), f"{transport_name} fanout failed to quiesce"
    assert set(calls) == set(peers), f"{transport_name} did not attempt every peer"
    assert peak >= 2, f"{transport_name} did not propagate concurrently"
    assert peak <= core.MAX_PROPAGATION_WORKERS, (
        f"{transport_name} exceeded bounded worker limit"
    )
    assert all(core.peer_last_error.get(peer) for peer in peers)
    assert set(core.peer_resolved_hosts) == set(peers)
    return peak


def main():
    checks = 0

    assert AxvenCore.MAX_PROPAGATION_WORKERS == 16
    checks += 1
    print("[GREEN] propagation worker cap pinned at 16")

    tx_peak = _exercise(
        "_propagate_tx_outbound", "propagate_tx", FakeTx(), 22300
    )
    checks += 1
    print(f"[GREEN] TX propagation uses bounded concurrent fanout (peak={tx_peak})")

    block_peak = _exercise(
        "_propagate_block_outbound", "propagate_block", FakeBlock(), 22400
    )
    checks += 1
    print(
        f"[GREEN] block propagation uses bounded concurrent fanout (peak={block_peak})"
    )

    # The hardening is service-layer scheduling only. It must not alter any
    # consensus or activation identity.
    import axven
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == (
        "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    )
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
    checks += 1
    print("[GREEN] consensus and PQ activation identity unchanged")

    assert checks == 4
    print("SEC-223 bounded propagation fanout: 4/4 GREEN")


if __name__ == "__main__":
    main()
