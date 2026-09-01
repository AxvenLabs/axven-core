#!/usr/bin/env python3
"""SEC-230: daemon validation must not share the default explorer port."""
from __future__ import annotations

from pathlib import Path

import axven

DAEMON_REHEARSALS = (
    "daemon_lifecycle_test.py",
    "checkpoint42_peer_reconnect_spec.py",
    "checkpoint46_peer_retry_scheduler_spec.py",
    "checkpoint47_peer_retry_daemon_spec.py",
    "checkpoint48_peer_retry_recovery_spec.py",
    "checkpoint51_peer_health_transitions_daemon_spec.py",
    "checkpoint52_peer_health_history_daemon_spec.py",
    "checkpoint53_peer_health_incidents_daemon_spec.py",
    "checkpoint54_peer_health_incident_history_daemon_spec.py",
)


def main() -> None:
    checks = 0

    for name in DAEMON_REHEARSALS:
        source = Path(name).read_text(encoding="utf-8")
        assert "axven_core.py" in source, name
        assert '"run"' in source or "'run'" in source, name
        assert '"--explorer-port"' in source or "'--explorer-port'" in source, name
    checks += 1
    print("[GREEN] every production-daemon rehearsal selects an explicit explorer port")

    explorer_source = Path("explorer.py").read_text(encoding="utf-8")
    assert "if port < 0 or port > 65535:" in explorer_source
    assert 'port=0' in explorer_source
    checks += 1
    print("[GREEN] ExplorerServer keeps port zero as the kernel-selected ephemeral-port contract")

    for name in DAEMON_REHEARSALS:
        source = Path(name).read_text(encoding="utf-8")
        assert '"--rpc-port"' in source or "'--rpc-port'" in source, name
        assert '"--p2p-port"' in source or "'--p2p-port'" in source, name
    checks += 1
    print("[GREEN] daemon rehearsals explicitly isolate RPC, P2P and explorer services")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-230 leaves canonical chain identity unchanged")

    print(f"SEC-230 daemon service-port isolation: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
