#!/usr/bin/env python3
"""SEC-103 outbound peer retry snapshot atomicity contract."""

import threading
import time
from pathlib import Path

import axven_core
from core import AxvenCore


RETRY_STATE = (
    "peer_retry_delay_seconds",
    "peer_next_retry_at",
    "peer_retry_base_interval",
)


def assert_retry_state_absent(core, peer):
    for name in RETRY_STATE:
        assert peer not in getattr(core, name), f"{name} recreated removed peer"
    assert peer not in core.peer_health_current_state, "health state recreated removed peer"


def main():
    checks = 0
    peer = ("127.0.0.1", 19106)

    core = AxvenCore()
    core.add_outbound_peer(peer)
    assert axven_core._schedule_peer_retry_if_configured(
        core, peer, 0.5, 0.5
    ) is True
    assert core.peer_retry_delay_seconds[peer] == 0.5
    assert core.peer_retry_base_interval[peer] == 0.5
    checks += 1
    print("[GREEN] configured peer base retry schedule preserved")

    core.remove_outbound_peer(peer)
    assert axven_core._schedule_peer_retry_if_configured(
        core, peer, 0.5, 0.5
    ) is False
    assert_retry_state_absent(core, peer)
    checks += 1
    print("[GREEN] removed peer cannot regain base retry metadata")

    core = AxvenCore()
    core.add_outbound_peer(peer)
    core.peer_consecutive_failures[peer] = 2
    core.remove_outbound_peer(peer)
    assert axven_core._reschedule_peer_after_sync(
        core, peer, 0.5, 60.0
    ) is None
    assert_retry_state_absent(core, peer)
    checks += 1
    print("[GREEN] removed peer cannot regain post-sync retry state")

    core = AxvenCore()
    core.add_outbound_peer(peer)
    core.peer_last_error[peer] = "ConnectionRefusedError: offline"
    core.peer_consecutive_failures[peer] = 2

    entered = threading.Event()
    release = threading.Event()
    remover_started = threading.Event()
    remover_done = threading.Event()
    result = []
    original_retry_delay = core.peer_retry_delay

    def blocked_retry_delay(*_args, **_kwargs):
        entered.set()
        assert release.wait(1.0), "retry calculation release timed out"
        return 1.0

    def remove_peer():
        remover_started.set()
        core.remove_outbound_peer(peer)
        remover_done.set()

    core.peer_retry_delay = blocked_retry_delay
    try:
        worker = threading.Thread(
            target=lambda: result.append(
                axven_core._reschedule_peer_after_sync(core, peer, 0.5, 60.0)
            ),
            daemon=True,
        )
        worker.start()
        assert entered.wait(1.0), "atomic retry reschedule did not start"

        remover = threading.Thread(target=remove_peer, daemon=True)
        remover.start()
        assert remover_started.wait(1.0), "peer remover did not start"
        time.sleep(0.1)
        assert not remover_done.is_set(), "peer removal bypassed retry snapshot lock"

        release.set()
        worker.join(2.0)
        remover.join(2.0)
        assert result == [1.0]
        assert remover_done.is_set()
        assert_retry_state_absent(core, peer)
    finally:
        release.set()
        core.peer_retry_delay = original_retry_delay

    checks += 1
    print("[GREEN] concurrent removal cleans completed retry snapshot atomically")

    source = Path(axven_core.__file__).read_text(encoding="utf-8")
    assert source.count("_schedule_peer_retry_if_configured(") == 3
    assert source.count("_reschedule_peer_after_sync(") == 2
    assert source.index("core.sync_outbound_peer(addr)") < source.rindex(
        "_reschedule_peer_after_sync("
    )
    checks += 1
    print("[GREEN] daemon retry paths use atomic helpers after network sync")

    print(f"SEC-103 peer retry snapshot atomicity: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
