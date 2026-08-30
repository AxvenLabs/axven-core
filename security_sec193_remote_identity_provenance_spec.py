#!/usr/bin/env python3
"""SEC-193: preserve verified remote P2P identity provenance in operator tools."""
from __future__ import annotations

import inspect
from pathlib import Path

import axven
import p2p

ROOT = Path(__file__).resolve().parent


class DummySocket:
    def __init__(self):
        self.timeouts = []
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


def main():
    checks = []

    def green(name, condition=True):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    remote_hello = {
        "type": "hello",
        "protocol_version": 777,
        "chain_id": "sentinel-remote-chain",
        "config_fingerprint": "remote-fingerprint",
        "genesis_hash": "remote-genesis",
    }
    expected_identity = {
        key: remote_hello[key]
        for key in (
            "protocol_version",
            "chain_id",
            "config_fingerprint",
            "genesis_hash",
        )
    }
    dummy = DummySocket()
    calls = {}
    original_create = p2p.socket.create_connection
    original_handshake = p2p.handshake

    def fake_create(address, timeout=None):
        calls["address"] = address
        calls["timeout"] = timeout
        return dummy

    def fake_handshake(sock, deadline=None):
        calls["handshake_sock"] = sock
        calls["deadline"] = deadline
        return dict(remote_hello)

    p2p.socket.create_connection = fake_create
    p2p.handshake = fake_handshake
    try:
        returned_sock, remote_identity = p2p.connect_with_identity(
            ("203.0.113.7", 18444), timeout=7.0
        )
    finally:
        p2p.socket.create_connection = original_create
        p2p.handshake = original_handshake

    green(
        "connect_with_identity returns identity from verified peer hello",
        returned_sock is dummy
        and remote_identity == expected_identity
        and "type" not in remote_identity,
    )
    green(
        "connect_with_identity preserves outbound timeout and deadline semantics",
        calls.get("address") == ("203.0.113.7", 18444)
        and calls.get("timeout") == 7.0
        and calls.get("handshake_sock") is dummy
        and calls.get("deadline") is not None
        and dummy.timeouts == [7.0, 7.0],
    )

    original_connect_with_identity = p2p.connect_with_identity
    legacy_dummy = DummySocket()
    legacy_calls = {}

    def fake_connect_with_identity(address, timeout=3.0):
        legacy_calls["address"] = address
        legacy_calls["timeout"] = timeout
        return legacy_dummy, {"chain_id": "remote"}

    p2p.connect_with_identity = fake_connect_with_identity
    try:
        legacy_result = p2p.connect(("198.51.100.9", 18444), timeout=2.5)
    finally:
        p2p.connect_with_identity = original_connect_with_identity

    green(
        "legacy connect API remains socket-only and delegates once",
        legacy_result is legacy_dummy
        and legacy_calls == {
            "address": ("198.51.100.9", 18444),
            "timeout": 2.5,
        },
    )

    server = p2p.NodeServer().start()
    live_sock = None
    try:
        live_sock, live_identity = p2p.connect_with_identity(
            server.address, timeout=3.0
        )
        live_status = p2p.request(live_sock, {"type": "get_status"})
    finally:
        if live_sock is not None:
            live_sock.close()
        server.stop()
    green(
        "live canonical handshake exposes verified remote identity and usable socket",
        live_identity == p2p.local_identity()
        and live_status.get("type") == "status",
    )

    helper_src = "".join(inspect.getsource(p2p.connect_with_identity).split())
    legacy_src = "".join(inspect.getsource(p2p.connect).split())
    core_provenance_ok = (
        ("peer=handshake(s,deadline=deadline)" in helper_src)
        and (
            'forkeyin("protocol_version","chain_id","config_fingerprint","genesis_hash")'
            in helper_src
        )
        and ("local_identity" not in helper_src)
        and ("connect_with_identity(address,timeout=timeout)" in legacy_src)
        and ("handshake(" not in legacy_src)
    )
    green(
        "core returns handshake-derived identity without rebuilding local identity",
        core_provenance_ok,
    )

    peer_probe_src = (ROOT / "tools" / "peer_probe.py").read_text(encoding="utf-8")
    green(
        "peer probe reports handshake-derived remote identity",
        "p2p.connect_with_identity" in peer_probe_src
        and "p2p.local_identity()" not in peer_probe_src,
    )

    acceptance_src = (ROOT / "tools" / "public_peer_acceptance.py").read_text(
        encoding="utf-8"
    )
    green(
        "public peer acceptance reports handshake-derived remote identity",
        "p2p.connect_with_identity" in acceptance_src
        and "p2p.local_identity()" not in acceptance_src,
    )

    seed_src = (ROOT / "tools" / "seed_health.py").read_text(encoding="utf-8")
    green(
        "seed health uses remote identity and current protocol version",
        "p2p.connect_with_identity" in seed_src
        and "p2p.local_identity()" not in seed_src
        and "p2p.PROTOCOL_VERSION" in seed_src,
    )

    green(
        "SEC-193 leaves chain identity, protocol, and PQ activation semantics unchanged",
        p2p.PROTOCOL_VERSION == 2
        and axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks) == 9
    print("SEC-193 remote identity provenance: 9/9 GREEN")


if __name__ == "__main__":
    main()
