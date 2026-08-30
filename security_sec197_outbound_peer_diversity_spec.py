#!/usr/bin/env python3
"""SEC-197: outbound peer configuration must resist simple Sybil concentration."""
from __future__ import annotations

import axven
from core import AxvenCore


def expect_diversity_reject(core, peer):
    before = core.outbound_peer_addresses()
    try:
        core.add_outbound_peer(peer)
    except ValueError as exc:
        assert "divers" in str(exc).lower() or "netgroup" in str(exc).lower(), str(exc)
    else:
        raise AssertionError(f"Sybil-concentrated peer accepted: {peer!r}")
    assert core.outbound_peer_addresses() == before


def main():
    checks = []

    def green(name, condition=True):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    assert AxvenCore.MAX_OUTBOUND_PEERS_PER_NETGROUP == 2

    # Multiple ports on addresses controlled from one IPv4 /24 must not be
    # able to monopolize configured outbound slots.
    ipv4 = AxvenCore()
    ipv4.add_outbound_peer(("203.0.113.10", 18444))
    ipv4.add_outbound_peer(("203.0.113.11", 18445))
    expect_diversity_reject(ipv4, ("203.0.113.12", 18446))
    green("IPv4 /24 Sybil concentration is capped")

    ipv4.add_outbound_peer(("198.51.100.10", 18444))
    green(
        "distinct IPv4 netgroups remain usable",
        ("198.51.100.10", 18444) in ipv4.outbound_peer_addresses(),
    )

    # IPv6 gets the same policy at /64, matching the operational boundary of
    # a typical routed subnet rather than treating attacker-chosen addresses
    # as independent peers.
    ipv6 = AxvenCore()
    ipv6.add_outbound_peer(("2001:db8:1:2::10", 18444))
    ipv6.add_outbound_peer(("2001:db8:1:2::11", 18445))
    expect_diversity_reject(ipv6, ("2001:db8:1:2::12", 18446))
    ipv6.add_outbound_peer(("2001:db8:1:3::10", 18444))
    green("IPv6 /64 Sybil concentration is capped while distinct /64 survives")

    # Do not perform DNS resolution in a security policy. Canonicalize the
    # operator-supplied DNS name itself so case/trailing-dot aliases cannot
    # mint unlimited independent slots.
    dns = AxvenCore()
    dns.add_outbound_peer(("Seed.Example", 18444))
    dns.add_outbound_peer(("seed.example.", 18445))
    expect_diversity_reject(dns, ("SEED.EXAMPLE", 18446))
    green("DNS host aliases share one diversity bucket")

    # Duplicate endpoint registration stays idempotent and does not consume a
    # fresh diversity slot.
    duplicate = AxvenCore()
    peer = duplicate.add_outbound_peer(("192.0.2.10", 18444))
    duplicate.add_outbound_peer(peer)
    duplicate.add_outbound_peer(("192.0.2.11", 18445))
    expect_diversity_reject(duplicate, ("192.0.2.12", 18446))
    green("duplicate endpoint remains idempotent under diversity accounting")

    # Rejection must happen before the persisted peer callback sees unsafe
    # topology.
    persisted = []
    guarded = AxvenCore()
    guarded.peer_persist_callback = lambda peers: persisted.append(list(peers))
    guarded.add_outbound_peer(("203.0.114.1", 18444))
    guarded.add_outbound_peer(("203.0.114.2", 18445))
    before_callbacks = len(persisted)
    expect_diversity_reject(guarded, ("203.0.114.3", 18446))
    green(
        "diversity rejection occurs before persistence publication",
        len(persisted) == before_callbacks,
    )

    # Loopback is a local multi-node development boundary, not an Internet
    # routing identity. Keep local rehearsals usable while public/routable
    # peers remain diversity-capped.
    local = AxvenCore()
    for port in (18444, 18445, 18446, 18447):
        local.add_outbound_peer(("127.0.0.1", port))
    green("loopback multi-node development remains exempt")

    green(
        "SEC-197 preserves consensus and protocol identity",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks) == 8
    print("SEC-197 outbound peer diversity: 8/8 GREEN")


if __name__ == "__main__":
    main()
