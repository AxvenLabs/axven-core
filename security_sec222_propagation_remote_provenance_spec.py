#!/usr/bin/env python3
"""SEC-222: TX/block propagation must preserve resolved remote-IP provenance."""
from __future__ import annotations

import inspect
from pathlib import Path

import axven
import p2p
from core import AxvenCore

ROOT = Path(__file__).resolve().parent


class DummySocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class StubTx:
    def to_dict(self):
        return {"sentinel": "tx"}

    def txid(self):
        return "a" * 64


class StubBlock:
    def to_dict(self):
        return {"sentinel": "block"}

    def hash(self):
        return "b" * 64


def main():
    checks = []

    def green(label, condition=True):
        assert condition, label
        checks.append(label)
        print("[GREEN]", label)

    tx = StubTx()
    block = StubBlock()

    original_connect = p2p.connect
    original_request = p2p.request
    tx_sock = DummySocket()
    tx_seen = []

    def fake_tx_connect(address, timeout=3.0, remote_host_gate=None):
        assert address == ("tx-alias.example", 18444)
        assert callable(remote_host_gate)
        assert remote_host_gate("203.0.113.44") is True
        tx_seen.append("connect")
        return tx_sock

    def fake_tx_request(sock, msg, deadline=None):
        assert sock is tx_sock
        assert msg == {"type": "tx", "tx": tx.to_dict()}
        tx_seen.append("request")
        return {"type": "accepted", "kind": "tx", "id": tx.txid()}

    p2p.connect = fake_tx_connect
    p2p.request = fake_tx_request
    try:
        tx_gate_hosts = []
        reply = p2p.propagate_tx(
            ("tx-alias.example", 18444),
            tx,
            remote_host_gate=lambda host: tx_gate_hosts.append(host) or True,
        )
    finally:
        p2p.connect = original_connect
        p2p.request = original_request

    green(
        "TX propagation forwards the resolved-host gate into the connection path",
        reply["id"] == tx.txid()
        and tx_gate_hosts == ["203.0.113.44"]
        and tx_seen == ["connect", "request"]
        and tx_sock.closed,
    )

    block_sock = DummySocket()
    block_seen = []

    def fake_block_connect(address, timeout=3.0, remote_host_gate=None):
        assert address == ("block-alias.example", 18445)
        assert callable(remote_host_gate)
        assert remote_host_gate("198.51.100.55") is True
        block_seen.append("connect")
        return block_sock

    def fake_block_request(sock, msg, deadline=None):
        assert sock is block_sock
        assert msg == {"type": "block", "block": block.to_dict()}
        block_seen.append("request")
        return {
            "type": "accepted",
            "kind": "block",
            "id": block.hash(),
            "status": "extended",
        }

    p2p.connect = fake_block_connect
    p2p.request = fake_block_request
    try:
        block_gate_hosts = []
        reply = p2p.propagate_block(
            ("block-alias.example", 18445),
            block,
            remote_host_gate=lambda host: block_gate_hosts.append(host) or True,
        )
    finally:
        p2p.connect = original_connect
        p2p.request = original_request

    green(
        "block propagation forwards the resolved-host gate into the connection path",
        reply["id"] == block.hash()
        and block_gate_hosts == ["198.51.100.55"]
        and block_seen == ["connect", "request"]
        and block_sock.closed,
    )

    denied_request = []

    def deny_connect(address, timeout=3.0, remote_host_gate=None):
        assert callable(remote_host_gate)
        if remote_host_gate("192.0.2.66") is not True:
            raise p2p.ProtocolError("outbound peer resolved diversity limit exceeded")
        raise AssertionError("denied gate unexpectedly allowed connection")

    def forbidden_request(sock, msg, deadline=None):
        denied_request.append(msg)
        raise AssertionError("payload request ran after remote-host denial")

    p2p.connect = deny_connect
    p2p.request = forbidden_request
    try:
        try:
            p2p.propagate_tx(
                ("denied-alias.example", 18446),
                tx,
                remote_host_gate=lambda host: False,
            )
            denied = False
        except p2p.ProtocolError:
            denied = True
    finally:
        p2p.connect = original_connect
        p2p.request = original_request

    green(
        "resolved-host denial stops TX propagation before payload transmission",
        denied and denied_request == [],
    )

    tx_core = AxvenCore()
    tx_addr = tx_core.add_outbound_peer(("core-tx-alias.example", 19001))
    original_propagate_tx = p2p.propagate_tx

    def fake_core_tx(address, candidate, remote_host_gate=None):
        assert address == tx_addr and candidate is tx
        assert callable(remote_host_gate)
        if remote_host_gate("9.9.9.9") is not True:
            raise p2p.ProtocolError("resolved host rejected")
        return {"type": "accepted", "kind": "tx", "id": tx.txid()}

    p2p.propagate_tx = fake_core_tx
    try:
        tx_core._propagate_tx_outbound(tx)
    finally:
        p2p.propagate_tx = original_propagate_tx

    green(
        "configured TX propagation records the actual resolved peer IP",
        tx_core.peer_resolved_hosts.get(tx_addr) == "9.9.9.9"
        and tx_core.peer_last_error.get(tx_addr) is None,
    )

    block_core = AxvenCore()
    block_addr = block_core.add_outbound_peer(("core-block-alias.example", 19002))
    original_propagate_block = p2p.propagate_block

    def fake_core_block(address, candidate, remote_host_gate=None):
        assert address == block_addr and candidate is block
        assert callable(remote_host_gate)
        if remote_host_gate("1.0.0.8") is not True:
            raise p2p.ProtocolError("resolved host rejected")
        return {
            "type": "accepted",
            "kind": "block",
            "id": block.hash(),
            "status": "extended",
        }

    p2p.propagate_block = fake_core_block
    try:
        block_core._propagate_block_outbound(block)
    finally:
        p2p.propagate_block = original_propagate_block

    green(
        "configured block propagation records the actual resolved peer IP",
        block_core.peer_resolved_hosts.get(block_addr) == "1.0.0.8"
        and block_core.peer_last_error.get(block_addr) is None,
    )

    diversity = AxvenCore()
    peers = [
        diversity.add_outbound_peer((f"alias-{index}.example", 20000 + index))
        for index in range(1, 6)
    ]
    for index in range(4):
        assert diversity._admit_resolved_peer_host(
            peers[index], f"8.8.8.{index + 1}"
        )

    def fake_diversity_tx(address, candidate, remote_host_gate=None):
        assert callable(remote_host_gate)
        if address == peers[4]:
            if remote_host_gate("8.8.8.5") is not True:
                raise p2p.ProtocolError(
                    "outbound peer resolved diversity limit exceeded"
                )
        return {"type": "accepted", "kind": "tx", "id": tx.txid()}

    p2p.propagate_tx = fake_diversity_tx
    try:
        diversity._propagate_tx_outbound(tx)
    finally:
        p2p.propagate_tx = original_propagate_tx

    green(
        "propagation rejects a fifth DNS alias resolving into one IPv4 /24",
        peers[4] not in diversity.peer_resolved_hosts
        and "resolved diversity limit exceeded"
        in diversity.peer_last_error.get(peers[4], ""),
    )

    p2p_source = (ROOT / "p2p.py").read_text(encoding="utf-8")
    core_source = (ROOT / "core.py").read_text(encoding="utf-8")
    green(
        "production propagation APIs and bounded core fanout carry remote-host provenance",
        "def propagate_tx(address,tx,remote_host_gate=None):" in p2p_source
        and "def propagate_block(address,block,remote_host_gate=None):" in p2p_source
        and "transport(addr,payload,remote_host_gate=remote_host_gate)" in core_source
        and "self._propagate_outbound(tx,p2p.propagate_tx)" in core_source
        and "self._propagate_outbound(block,p2p.propagate_block)" in core_source
        and "remote_host_gate=self._admit_resolved_peer_host" not in core_source,
    )

    green(
        "SEC-222 leaves canonical chain, protocol, and PQ activation semantics unchanged",
        p2p.PROTOCOL_VERSION == 3
        and axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks) == 8, len(checks)
    print("SEC-222 propagation remote provenance: 8/8 GREEN")


if __name__ == "__main__":
    main()
