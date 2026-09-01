#!/usr/bin/env python3
"""SEC-225: daemon retry scheduling must not serialize peer latency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import inspect
import threading
import time

import axven
import axven_core
from core import AxvenCore


def main():
    checks = 0

    # Fail first on the pre-SEC-225 scheduler: periodic retries must not call
    # one peer synchronously from the daemon's main scheduling loop.
    source = inspect.getsource(axven_core.main)
    assert "core.sync_outbound_peer(addr)" not in source, (
        "daemon retry scheduler remains serial"
    )
    checks += 1
    print("[GREEN] daemon scheduler has no serial per-peer sync call")

    assert getattr(axven_core, "MAX_DAEMON_SYNC_WORKERS", None) == 16
    assert hasattr(axven_core, "_submit_due_peer_syncs")
    assert hasattr(axven_core, "_reap_completed_peer_syncs")
    checks += 1
    print("[GREEN] daemon retry worker cap and bounded scheduler helpers present")

    core = AxvenCore()
    peers = [(f"127.0.2.{i + 1}", 22500 + i) for i in range(24)]
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
        return {
            "peer": f"{addr[0]}:{addr[1]}",
            "ok": False,
            "error": "simulated slow peer",
        }

    core.sync_outbound_peer = blocked_sync_one
    peer_next_sync = {peer: 0.0 for peer in peers}
    inflight = {}
    executor = ThreadPoolExecutor(max_workers=axven_core.MAX_DAEMON_SYNC_WORKERS)
    try:
        submitted = axven_core._submit_due_peer_syncs(
            core, executor, inflight, peer_next_sync, now=time.monotonic()
        )
        assert submitted == axven_core.MAX_DAEMON_SYNC_WORKERS
        assert len(inflight) == axven_core.MAX_DAEMON_SYNC_WORKERS
        assert entered_two.wait(0.75), "daemon retry fanout did not run concurrently"
        assert peak >= 2
        assert peak <= axven_core.MAX_DAEMON_SYNC_WORKERS

        # No unbounded future queue: when every worker is occupied, the
        # scheduler must leave the remaining due peers for a later tick.
        assert axven_core._submit_due_peer_syncs(
            core, executor, inflight, peer_next_sync, now=time.monotonic()
        ) == 0
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=False)
        core.sync_outbound_peer = original_sync_one

    assert axven_core._reap_completed_peer_syncs(
        core, inflight, peer_next_sync, 0.5
    ) == axven_core.MAX_DAEMON_SYNC_WORKERS
    assert not inflight
    assert len(calls) == axven_core.MAX_DAEMON_SYNC_WORKERS
    checks += 1
    print(f"[GREEN] daemon retry fanout is concurrent and bounded (peak={peak})")

    # The daemon must quiesce outbound retry workers before the final chain
    # snapshot, otherwise a worker could mutate chain state during persistence.
    shutdown_anchor = "peer_sync_executor.shutdown(wait=True, cancel_futures=False)"
    persist_anchor = "_shutdown_services_and_persist(dd,core,rpc,explorer)"
    assert shutdown_anchor in source
    assert source.rfind(shutdown_anchor) < source.rfind(persist_anchor)
    checks += 1
    print("[GREEN] daemon retry workers quiesce before final persistence")

    # Scheduling hardening only: canonical consensus/PQ identity stays fixed.
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
    checks += 1
    print("[GREEN] consensus and PQ activation identity unchanged")

    assert checks == 5
    print("SEC-225 bounded daemon retry fanout: 5/5 GREEN")


if __name__ == "__main__":
    main()
