#!/usr/bin/env python3
"""SEC-224: bulk outbound sync must not serialize peer latency."""

from __future__ import annotations

import threading

from core import AxvenCore


def main():
    checks = 0
    core = AxvenCore()
    peers = [(f"127.0.1.{i + 1}", 22400 + i) for i in range(8)]
    for peer in peers:
        core.add_outbound_peer(peer)

    entered_two = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = 0
    peak = 0
    calls = []

    original_sync_one = core.sync_outbound_peer

    def blocked_sync_one(peer):
        nonlocal active, peak
        addr = core._parse_peer(peer)
        with lock:
            calls.append(addr)
            active += 1
            peak = max(peak, active)
            if active >= 2:
                entered_two.set()
        release.wait(2.0)
        with lock:
            active -= 1
        return {"peer": f"{addr[0]}:{addr[1]}", "ok": False, "error": "simulated slow peer"}

    core.sync_outbound_peer = blocked_sync_one
    result = []
    worker = threading.Thread(
        target=lambda: result.extend(core.sync_outbound_peers()), daemon=True
    )
    try:
        worker.start()
        assert entered_two.wait(0.75), "bulk outbound sync fanout remains serial"
    finally:
        release.set()
        worker.join(5.0)
        core.sync_outbound_peer = original_sync_one

    assert not worker.is_alive(), "bulk outbound sync fanout failed to quiesce"
    assert set(calls) == set(peers), "bulk outbound sync did not attempt every peer"
    assert peak >= 2, "bulk outbound sync did not run concurrently"
    assert peak <= core.MAX_SYNC_WORKERS, "bulk outbound sync exceeded worker cap"
    assert len(result) == len(peers), "bulk outbound sync result cardinality changed"
    checks += 1
    print(f"[GREEN] bulk outbound sync uses bounded concurrent fanout (peak={peak})")

    assert core.MAX_SYNC_WORKERS == 16
    checks += 1
    print("[GREEN] bulk outbound sync worker cap pinned at 16")

    # Scheduling hardening only: canonical chain/PQ identity must stay unchanged.
    import axven
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
    checks += 1
    print("[GREEN] consensus and PQ activation identity unchanged")

    assert checks == 3
    print("SEC-224 bounded bulk sync fanout: 3/3 GREEN")


if __name__ == "__main__":
    main()
