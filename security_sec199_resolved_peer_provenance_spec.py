#!/usr/bin/env python3
"""SEC-199: bind outbound diversity and work accounting to the resolved peer IP."""
from __future__ import annotations

import axven
import p2p
from core import AxvenCore


class DummySocket:
    def __init__(self, remote_host):
        self.remote_host=remote_host
        self.closed=False
        self.timeouts=[]
    def settimeout(self,value):
        self.timeouts.append(value)
    def getpeername(self):
        return (self.remote_host,18444)
    def close(self):
        self.closed=True


class RecordingLimiter:
    def __init__(self):
        self.calls=[]
    def consume(self,host,*args):
        self.calls.append((host,*args))
        return True


def main():
    checks=[]
    def green(label,condition):
        assert condition,label
        checks.append(label)
        print("[GREEN]",label)

    original_create=p2p.socket.create_connection
    original_handshake=p2p.handshake
    rejected=DummySocket("8.8.8.77")
    order=[]
    p2p.socket.create_connection=lambda address,timeout=None: rejected
    def forbidden_handshake(sock,deadline=None):
        order.append("handshake")
        return {"type":"hello",**p2p.local_identity()}
    p2p.handshake=forbidden_handshake
    try:
        try:
            p2p.connect_with_identity(
                ("alias-one.example",18444),
                timeout=3.0,
                remote_host_gate=lambda host: order.append(("gate",host)) or False,
            )
            denied=False
        except p2p.ProtocolError as exc:
            denied="resolved diversity limit exceeded" in str(exc)
    finally:
        p2p.socket.create_connection=original_create
        p2p.handshake=original_handshake
    green(
        "resolved peer gate runs before handshake work and closes rejected sockets",
        denied and order==[("gate","8.8.8.77")] and rejected.closed,
    )

    allowed=DummySocket("1.1.1.9")
    seen=[]
    p2p.socket.create_connection=lambda address,timeout=None: allowed
    p2p.handshake=lambda sock,deadline=None: {"type":"hello",**p2p.local_identity()}
    try:
        sock,identity=p2p.connect_with_identity(
            ("alias-two.example",18444),
            timeout=2.0,
            remote_host_gate=lambda host: seen.append(host) or True,
        )
    finally:
        p2p.socket.create_connection=original_create
        p2p.handshake=original_handshake
    green(
        "accepted connections expose the actual kernel peer IP to the gate",
        sock is allowed and seen==["1.1.1.9"] and identity==p2p.local_identity(),
    )
    sock.close()

    core=AxvenCore()
    peers=[]
    for i in range(1,6):
        peers.append(core.add_outbound_peer((f"seed-{i}.example",18000+i)))
    green(
        "distinct DNS aliases remain representable before resolution",
        len(core.outbound_peers)==5,
    )
    first_four=[
        core._admit_resolved_peer_host(peers[i],f"8.8.8.{i+1}")
        for i in range(4)
    ]
    fifth=core._admit_resolved_peer_host(peers[4],"8.8.8.5")
    green(
        "fifth DNS alias resolving into one IPv4 /24 is rejected",
        all(first_four) and fifth is False
        and peers[4] not in core.peer_resolved_hosts,
    )
    green(
        "the rejected alias is admissible when it resolves into a distinct /24",
        core._admit_resolved_peer_host(peers[4],"8.8.9.5") is True
        and core.peer_resolved_hosts[peers[4]]=="8.8.9.5",
    )

    ipv6=AxvenCore()
    v6_peers=[
        ipv6.add_outbound_peer((f"v6-{i}.example",19000+i))
        for i in range(1,6)
    ]
    for i in range(4):
        assert ipv6._admit_resolved_peer_host(
            v6_peers[i],f"2606:4700:4700::{i+1}"
        )
    green(
        "resolved IPv6 aliases share the existing /48 diversity boundary",
        ipv6._admit_resolved_peer_host(
            v6_peers[4],"2606:4700:4700::5"
        ) is False,
    )

    tracked=AxvenCore()
    addr=tracked.add_outbound_peer(("budget-alias.example",20001))
    block_limiter=RecordingLimiter()
    sig_limiter=RecordingLimiter()
    tracked._outbound_sync_block_work_limiter=block_limiter
    tracked._outbound_sync_block_signature_work_limiter=sig_limiter
    original_sync=p2p.sync_to_peer
    def fake_sync(address,session,**kwargs):
        assert kwargs["remote_host_gate"]("9.9.9.9") is True
        assert kwargs["block_work_gate"]() is True
        assert kwargs["block_signature_work_gate"](5) is True
        return 1
    p2p.sync_to_peer=fake_sync
    try:
        result=tracked.sync_outbound_peer(addr)
    finally:
        p2p.sync_to_peer=original_sync
    green(
        "configured sync work budgets are keyed by resolved IP instead of DNS alias",
        result["ok"] is True and result["accepted"]==1
        and block_limiter.calls==[("9.9.9.9",)]
        and sig_limiter.calls==[("9.9.9.9",5)]
        and tracked.peer_resolved_hosts[addr]=="9.9.9.9",
    )

    manual=AxvenCore()
    manual_block=RecordingLimiter()
    manual_sig=RecordingLimiter()
    manual._outbound_sync_block_work_limiter=manual_block
    manual._outbound_sync_block_signature_work_limiter=manual_sig
    def fake_manual(address,session,**kwargs):
        assert kwargs["remote_host_gate"]("1.0.0.1") is True
        kwargs["block_work_gate"]()
        kwargs["block_signature_work_gate"](2)
        return 0
    p2p.sync_to_peer=fake_manual
    try:
        manual_result=manual.sync_peer("manual-alias.example",20002,1)
    finally:
        p2p.sync_to_peer=original_sync
    green(
        "manual sync per-host budgets also use the resolved peer IP",
        manual_result==0
        and manual_block.calls==[("1.0.0.1",)]
        and manual_sig.calls==[("1.0.0.1",2)],
    )

    removable=AxvenCore()
    removable_addr=removable.add_outbound_peer(("remove.example",21001))
    assert removable._admit_resolved_peer_host(removable_addr,"8.8.4.4")
    removable.remove_outbound_peer(removable_addr)
    green(
        "removing a configured peer clears resolved provenance state",
        removable_addr not in removable.peer_resolved_hosts,
    )

    green(
        "resolved peer provenance hardening leaves chain and protocol identity unchanged",
        p2p.PROTOCOL_VERSION==3
        and axven.CHAIN_ID=="axven-devnet-2"
        and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks)==10,len(checks)
    print("SEC-199 resolved peer provenance: 10/10 GREEN")


if __name__=="__main__":
    main()
