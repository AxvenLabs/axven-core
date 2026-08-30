#!/usr/bin/env python3
"""SEC-197: bound configured outbound peer eclipse/Sybil concentration."""

from __future__ import annotations

import inspect
import json
import os
import tempfile

import axven
from core import AxvenCore
from datadir import DataDir


def expect_value_error(fn, contains):
    try:
        fn()
    except ValueError as exc:
        assert contains in str(exc), str(exc)
        return True
    return False


def main():
    checks=[]
    def green(label, condition):
        assert condition, label
        checks.append(label)
        print("[GREEN]", label)

    green(
        "peer diversity policy constants pinned",
        AxvenCore.MAX_CONFIGURED_PEERS_PER_DIVERSITY_GROUP == 4
        and AxvenCore.PEER_DIVERSITY_IPV4_PREFIX == 24
        and AxvenCore.PEER_DIVERSITY_IPV6_PREFIX == 48,
    )
    green(
        "IPv4 routable peers are grouped by /24",
        AxvenCore._peer_diversity_group("8.8.8.1") == ("ipv4","8.8.8.0/24")
        and AxvenCore._peer_diversity_group("8.8.8.254") == ("ipv4","8.8.8.0/24")
        and AxvenCore._peer_diversity_group("8.8.9.1") == ("ipv4","8.8.9.0/24"),
    )
    green(
        "IPv6 routable peers are grouped by /48",
        AxvenCore._peer_diversity_group("2606:4700:4700::1")
            == ("ipv6","2606:4700:4700::/48")
        and AxvenCore._peer_diversity_group("2606:4700:4701::1")
            == ("ipv6","2606:4700:4701::/48"),
    )
    green(
        "DNS aliases share a canonical diversity group",
        AxvenCore._peer_diversity_group("Seed.Example.Org.")
            == ("dns","seed.example.org")
        and AxvenCore._peer_diversity_group("seed.example.org")
            == ("dns","seed.example.org"),
    )
    green(
        "loopback remains exempt for multi-node local devnet labs",
        AxvenCore._peer_diversity_group("127.0.0.1") is None
        and AxvenCore._peer_diversity_group("::1") is None
        and AxvenCore._peer_diversity_group("localhost") is None,
    )

    core=AxvenCore()
    for i,host in enumerate(("8.8.8.1","8.8.8.2","8.8.8.3","8.8.8.4")):
        core.add_outbound_peer((host,20000+i))
    before=list(core.outbound_peers)
    persisted=[]
    core.peer_persist_callback=lambda peers: persisted.append(list(peers))
    green(
        "fifth IPv4 endpoint in one /24 is rejected atomically",
        expect_value_error(
            lambda: core.add_outbound_peer(("8.8.8.5",20005)),
            "configured peer diversity limit exceeded",
        )
        and core.outbound_peers == before
        and not persisted,
    )
    green(
        "a distinct IPv4 /24 remains admissible after a group fills",
        core.add_outbound_peer(("8.8.9.1",20006)) == ("8.8.9.1",20006)
        and len(core.outbound_peers) == 5
        and len(persisted) == 1,
    )

    dns=AxvenCore()
    dns_hosts=("Seed.Example.Org","seed.example.org.","SEED.EXAMPLE.ORG","seed.example.org")
    for i,host in enumerate(dns_hosts):
        dns.add_outbound_peer((host,21000+i))
    dns_before=list(dns.outbound_peers)
    green(
        "case and trailing-dot DNS aliases cannot mint extra Sybil slots",
        expect_value_error(
            lambda: dns.add_outbound_peer(("SeEd.ExAmPlE.OrG.",21010)),
            "configured peer diversity limit exceeded",
        )
        and dns.outbound_peers == dns_before,
    )

    v6=AxvenCore()
    for i in range(1,5):
        v6.add_outbound_peer((f"2606:4700:4700::{i}",22000+i))
    green(
        "fifth IPv6 endpoint in one /48 is rejected while another /48 is allowed",
        expect_value_error(
            lambda: v6.add_outbound_peer(("2606:4700:4700::5",22005)),
            "configured peer diversity limit exceeded",
        )
        and v6.add_outbound_peer(("2606:4700:4701::1",22006))
            == ("2606:4700:4701::1",22006),
    )

    local=AxvenCore()
    for i in range(12):
        local.add_outbound_peer(("127.0.0.1",23000+i))
    green(
        "local multi-port devnet topology remains compatible",
        len(local.outbound_peers) == 12,
    )

    bad=[(f"8.8.8.{i}",24000+i) for i in range(1,6)]
    with tempfile.TemporaryDirectory() as td:
        dd=DataDir(td)
        green(
            "peer writer refuses to persist an eclipse-concentrated set",
            expect_value_error(
                lambda: dd.save_peers(bad),
                "configured peer diversity limit exceeded",
            )
            and not dd.peer_file.exists(),
        )

        dd.peer_file.write_text(
            json.dumps([{"host":host,"port":port} for host,port in bad]),
            encoding="utf-8",
        )
        if os.name == "posix":
            os.chmod(dd.peer_file,0o600)
        green(
            "persisted eclipse-concentrated peer sets fail closed on read",
            expect_value_error(
                dd.load_peers,
                "configured peer diversity limit exceeded",
            ),
        )

        good=[("8.8.8.1",25001),("8.8.9.1",25002),("1.1.1.1",25003)]
        dd.save_peers(good)
        green(
            "diverse persisted peer sets still round-trip canonically",
            dd.load_peers() == good,
        )

    add_src=inspect.getsource(AxvenCore.add_outbound_peer)
    save_src=inspect.getsource(DataDir.save_peers)
    load_src=inspect.getsource(DataDir.load_peers)
    green(
        "diversity gates precede runtime mutation and persistence publication",
        "_validate_peer_diversity([*self.outbound_peers,addr])" in add_src
        and add_src.index("_validate_peer_diversity([*self.outbound_peers,addr])")
            < add_src.index("self.outbound_peers.append(addr)")
        and "_validate_peer_diversity(normalized)" in save_src
        and "return AxvenCore._validate_peer_diversity(peers)" in load_src,
    )

    green(
        "peer diversity hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks) == 14, len(checks)
    print("SEC-197 peer diversity: 14/14 GREEN")


if __name__ == "__main__":
    main()
