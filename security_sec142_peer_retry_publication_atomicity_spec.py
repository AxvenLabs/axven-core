#!/usr/bin/env python3
"""SEC-142 publishes peer failure/success health and retry metadata atomically."""

import inspect
import threading
import time

import axven
import axven_core
import core as core_module
import p2p


def one_status(core):
    rows=core.outbound_peer_status()
    assert len(rows) == 1
    return rows[0]


def main():
    checks=0
    peer=("127.0.0.1",65530)
    core=core_module.AxvenCore()
    core.add_outbound_peer(peer)
    core.configure_peer_retry_publication(0.5,60.0)

    original_sync=p2p.sync_to_peer
    try:
        # Network I/O must remain outside the peer lock. An operator snapshot
        # must complete while the outbound socket call is still blocked.
        network_entered=threading.Event()
        network_release=threading.Event()
        network_result={}

        def slow_failure(*_args,**_kwargs):
            network_entered.set()
            assert network_release.wait(2.0)
            raise ConnectionRefusedError("sec142 offline")

        p2p.sync_to_peer=slow_failure
        worker=threading.Thread(
            target=lambda: network_result.setdefault("result",core.sync_outbound_peer(peer)),
            daemon=True,
        )
        worker.start()
        assert network_entered.wait(1.0)
        observer_result={}
        observer=threading.Thread(
            target=lambda: observer_result.setdefault("row",one_status(core)),
            daemon=True,
        )
        observer.start()
        observer.join(0.5)
        assert not observer.is_alive(), "peer lock held across outbound network I/O"
        assert observer_result["row"]["consecutive_failures"] == 0
        print("[GREEN] outbound network I/O remains outside peer-state lock"); checks+=1
        network_release.set()
        worker.join(2.0)
        assert not worker.is_alive()

        row=one_status(core)
        assert row["consecutive_failures"] == 1
        assert row["retry_delay_seconds"] == 0.5
        assert isinstance(row["next_retry_at"],str) and row["next_retry_at"].endswith("Z")
        assert row["retry_backoff_active"] is False
        print("[GREEN] first failure publishes coherent base retry snapshot"); checks+=1

        # Deterministically pause after retry schedule publication but before
        # the outer failure critical section releases. Readers must block.
        original_publish=core._publish_peer_retry_schedule_locked
        publish_entered=threading.Event()
        publish_release=threading.Event()

        def blocking_publish(addr):
            result=original_publish(addr)
            publish_entered.set()
            assert publish_release.wait(2.0)
            return result

        core._publish_peer_retry_schedule_locked=blocking_publish

        def immediate_failure(*_args,**_kwargs):
            raise ConnectionRefusedError("sec142 offline again")

        p2p.sync_to_peer=immediate_failure
        second_result={}
        second=threading.Thread(
            target=lambda: second_result.setdefault("result",core.sync_outbound_peer(peer)),
            daemon=True,
        )
        second.start()
        assert publish_entered.wait(1.0)

        blocked_result={}
        blocked_done=threading.Event()
        def read_while_publishing():
            blocked_result["row"]=one_status(core)
            blocked_done.set()
        blocked=threading.Thread(target=read_while_publishing,daemon=True)
        blocked.start()
        assert not blocked_done.wait(0.2), "reader observed partial retry publication"
        print("[GREEN] status reader blocks during failure plus retry publication"); checks+=1

        publish_release.set()
        second.join(2.0); blocked.join(2.0)
        assert not second.is_alive() and not blocked.is_alive()
        row=blocked_result["row"]
        assert row["consecutive_failures"] == 2
        assert row["retry_delay_seconds"] == 1.0
        assert row["retry_backoff_active"] is True
        assert isinstance(row["next_retry_at"],str) and row["next_retry_at"].endswith("Z")
        print("[GREEN] second failure snapshot exposes matching doubled retry metadata"); checks+=1
        core._publish_peer_retry_schedule_locked=original_publish

        # Recovery resets failures and publishes the base retry schedule in
        # the same result critical section.
        p2p.sync_to_peer=lambda *_args,**_kwargs: 0
        result=core.sync_outbound_peer(peer)
        assert result["ok"] is True
        row=one_status(core)
        assert row["last_error"] is None
        assert row["consecutive_failures"] == 0
        assert row["retry_delay_seconds"] == 0.5
        assert row["retry_backoff_active"] is False
        assert isinstance(row["next_retry_at"],str) and row["next_retry_at"].endswith("Z")
        print("[GREEN] successful recovery publishes reset health and base retry atomically"); checks+=1

        # Disabling the daemon policy preserves legacy direct-service behavior.
        core.configure_peer_retry_publication(None)
        before=row["next_retry_at"]
        time.sleep(0.01)
        p2p.sync_to_peer=immediate_failure
        core.sync_outbound_peer(peer)
        row=one_status(core)
        assert row["consecutive_failures"] == 1
        assert row["next_retry_at"] == before
        print("[GREEN] unconfigured direct sync preserves legacy retry publication ownership"); checks+=1
    finally:
        p2p.sync_to_peer=original_sync

    sync_src=inspect.getsource(core_module.AxvenCore.sync_outbound_peer)
    assert sync_src.index("p2p.sync_to_peer(") < sync_src.index("with _peer_guard(self):")
    assert sync_src.count("_publish_peer_retry_schedule_locked(addr)") == 2
    print("[GREEN] production sync keeps network work outside lock and publishes both outcomes"); checks+=1

    daemon_src=inspect.getsource(axven_core.main)
    configure_anchor="core.configure_peer_retry_publication(base_sync_interval,60.0)"
    initial_anchor="initial_sync=core.sync_outbound_peers()"
    assert configure_anchor in daemon_src and daemon_src.index(configure_anchor) < daemon_src.index(initial_anchor)
    print("[GREEN] daemon configures atomic retry publication before initial outbound sync"); checks+=1

    module_src=inspect.getsource(axven_core)
    assert module_src.count("_schedule_peer_retry_if_configured(") == 3
    assert module_src.count("_reschedule_peer_after_sync(") == 2
    assert "core.sync_outbound_peer(addr)" in module_src
    print("[GREEN] SEC-103 configured-peer retry helper wiring remains intact"); checks+=1

    assert (
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    )
    print("[GREEN] retry publication hardening leaves canonical chain identity unchanged"); checks+=1

    print(f"SEC-142 peer retry publication atomicity: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
