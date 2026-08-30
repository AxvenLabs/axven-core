#!/usr/bin/env python3
"""SEC-126 bound persisted and runtime configured-peer resource use."""

from __future__ import annotations

import inspect
import json
import tempfile
from pathlib import Path

import axven
import datadir
from core import AxvenCore
from datadir import DataDir


def expect_value_error(fn, text=None):
    try:
        fn()
    except ValueError as exc:
        return text is None or text in str(exc)
    return False


def main():
    checks=[]
    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "configured peer count and file-byte budgets pinned",
        AxvenCore.MAX_CONFIGURED_PEERS == 256
        and datadir.MAX_PEER_CONFIG_BYTES == 1024 * 1024,
    )

    with tempfile.TemporaryDirectory() as td:
        dd=DataDir(td)
        green("missing peer config remains an empty set", dd.load_peers() == [])

        canonical=[("seed.axven.org",18444),("127.0.0.1",19000)]
        dd.save_peers(canonical)
        green("canonical peer persistence round-trip preserved", dd.load_peers() == canonical)

        # The file-byte boundary must be enforced before UTF-8 or JSON parsing.
        dd.peer_file.write_bytes(b" " * (datadir.MAX_PEER_CONFIG_BYTES + 1))
        green(
            "oversized peer config rejected by bounded binary read",
            expect_value_error(dd.load_peers,"peer config too large"),
        )

        # Cardinality must be checked before per-peer parsing work begins.
        too_many=[{"host":"127.0.0.1","port":10000}] * (AxvenCore.MAX_CONFIGURED_PEERS + 1)
        dd.peer_file.write_text(json.dumps(too_many),encoding="utf-8")
        original_parse=AxvenCore._parse_peer
        parse_calls=[]
        def trap(peer):
            parse_calls.append(peer)
            raise AssertionError("peer parser must not run past list cardinality guard")
        AxvenCore._parse_peer=staticmethod(trap)
        try:
            list_guard=expect_value_error(dd.load_peers,"too many configured peers")
        finally:
            AxvenCore._parse_peer=staticmethod(original_parse)
        green(
            "oversized peer list rejected before per-peer parsing",
            list_guard and not parse_calls,
        )

        max_peers=[(f"peer-{i}.example",10000+i) for i in range(AxvenCore.MAX_CONFIGURED_PEERS)]
        dd.save_peers(max_peers)
        green(
            "exact configured-peer boundary persists and reloads",
            dd.load_peers() == max_peers,
        )

        # save_peers must reject before touching an existing good file.
        old_bytes=dd.peer_file.read_bytes()
        over=max_peers + [("overflow.example",20000)]
        green(
            "save rejects peer-count overflow without replacing prior config",
            expect_value_error(lambda: dd.save_peers(over),"too many configured peers")
            and dd.peer_file.read_bytes() == old_bytes,
        )

        yielded=[]
        def endlessish():
            for i in range(10000):
                yielded.append(i)
                yield (f"g-{i}.example",10000 + (i % 50000))
        green(
            "generator-backed peer save is consumption-bounded",
            expect_value_error(lambda: dd.save_peers(endlessish()),"too many configured peers")
            and len(yielded) == AxvenCore.MAX_CONFIGURED_PEERS + 1,
        )

        # json.dumps defaults to ensure_ascii=True.  Exercise the worst relevant
        # expansion shape to prove our own maximum valid save remains reloadable.
        unicode_host="😀" * 255
        unicode_peers=[(unicode_host,20000+i) for i in range(AxvenCore.MAX_CONFIGURED_PEERS)]
        dd.save_peers(unicode_peers)
        unicode_size=dd.peer_file.stat().st_size
        green(
            "maximum Unicode-heavy valid peer set fits its file budget",
            unicode_size <= datadir.MAX_PEER_CONFIG_BYTES
            and dd.load_peers() == unicode_peers,
        )

        # A config emitted at the exact boundary must remain restart-loadable.
        dd.save_peers(max_peers)
        loaded_core=dd.load_core()
        green(
            "load_core accepts a persisted peer set at the exact boundary",
            loaded_core.outbound_peers == max_peers,
        )

    core=AxvenCore()
    for i in range(AxvenCore.MAX_CONFIGURED_PEERS):
        core.add_outbound_peer((f"runtime-{i}.example",10000+i))
    before=list(core.outbound_peers)
    callback_calls=[]
    core.peer_persist_callback=lambda peers: callback_calls.append(list(peers))
    green(
        "runtime configured-peer boundary rejects a new overflow peer atomically",
        expect_value_error(
            lambda: core.add_outbound_peer(("runtime-overflow.example",30000)),
            "configured peer limit exceeded",
        )
        and core.outbound_peers == before
        and not callback_calls,
    )
    duplicate=before[-1]
    green(
        "duplicate peer remains idempotent at the configured-peer boundary",
        core.add_outbound_peer(duplicate) == duplicate
        and core.outbound_peers == before
        and not callback_calls,
    )

    load_src=inspect.getsource(DataDir.load_peers)
    secure_read_src=inspect.getsource(datadir._read_secure_peer_config_file)
    save_src=inspect.getsource(DataDir.save_peers)
    core_src=(Path(__file__).resolve().parent / "core.py").read_text(encoding="utf-8")
    green(
        "production persistence path bounds read count save count and payload bytes",
        "_read_secure_peer_config_file(self.peer_file)" in load_src
        and "f.read(MAX_PEER_CONFIG_BYTES+1)" in secure_read_src
        and "len(raw) > AxvenCore.MAX_CONFIGURED_PEERS" in load_src
        and "len(normalized) >= AxvenCore.MAX_CONFIGURED_PEERS" in save_src
        and "len(payload) > MAX_PEER_CONFIG_BYTES" in save_src,
    )
    green(
        "production runtime add path enforces configured-peer cardinality before mutation",
        "len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS" in core_src
        and core_src.index("len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS")
            < core_src.index("self.outbound_peers.append(addr)"),
    )

    green(
        "peer resource hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-126 peer config resource bounds: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
