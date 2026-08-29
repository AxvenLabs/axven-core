#!/usr/bin/env python3
"""SEC-144 exact peer/listener port type-domain regression contract."""

import json
import tempfile
from pathlib import Path

from core import AxvenCore
from datadir import DataDir
import p2p


def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def main():
    checks = 0

    assert AxvenCore._parse_peer(("127.0.0.1", 31337)) == ("127.0.0.1", 31337)
    checks += 1
    print("[GREEN] canonical tuple peer port preserved")

    assert AxvenCore._parse_peer(["node.axven.org", 65535]) == ("node.axven.org", 65535)
    checks += 1
    print("[GREEN] maximum structured peer port preserved")

    assert AxvenCore._parse_peer("node.axven.org:31337") == ("node.axven.org", 31337)
    checks += 1
    print("[GREEN] legacy textual host-port form preserved")

    for bad in ("31337", True, False, 31337.0, 31337.9, None, b"31337"):
        expect_value_error(
            lambda bad=bad: AxvenCore._parse_peer(("127.0.0.1", bad)),
            f"structured peer port type {type(bad).__name__} rejected",
        )
        checks += 1

    class Sneaky:
        called = False
        def __int__(self):
            self.called = True
            return 31337

    sneaky = Sneaky()
    expect_value_error(
        lambda: AxvenCore._parse_peer(("127.0.0.1", sneaky)),
        "structured peer object port rejected",
    )
    assert not sneaky.called
    checks += 1
    print("[GREEN] structured peer rejected without __int__ coercion")

    for bad in (0, -1, 65536):
        expect_value_error(
            lambda bad=bad: AxvenCore._parse_peer(("127.0.0.1", bad)),
            f"structured peer port bound {bad} rejected",
        )
        checks += 1

    with tempfile.TemporaryDirectory() as td:
        data = DataDir(td)
        data.peer_file.write_text(
            json.dumps([{"host": "127.0.0.1", "port": 31337}]),
            encoding="utf-8",
        )
        assert data.load_peers() == [("127.0.0.1", 31337)]
        checks += 1
        print("[GREEN] canonical persisted integer peer port preserved")

        for bad in ("31337", True, 31337.5, None):
            data.peer_file.write_text(
                json.dumps([{"host": "127.0.0.1", "port": bad}]),
                encoding="utf-8",
            )
            expect_value_error(
                data.load_peers,
                f"persisted peer port type {type(bad).__name__} rejected",
            )
            checks += 1

    original_sync = p2p.sync_to_peer
    sync_calls = []
    def fake_sync(*args, **kwargs):
        sync_calls.append((args, kwargs))
        return 0
    p2p.sync_to_peer = fake_sync
    try:
        core = object.__new__(AxvenCore)
        core.chain = object()
        core.mempool = object()
        for bad in ("31337", True, 31337.0):
            before = len(sync_calls)
            expect_value_error(
                lambda bad=bad: core.sync_peer("127.0.0.1", bad, 1),
                f"sync_peer port type {type(bad).__name__} rejected pre-I/O",
            )
            assert len(sync_calls) == before
            checks += 1
    finally:
        p2p.sync_to_peer = original_sync

    original_server = p2p.NodeServer
    server_calls = []
    class FakeNodeServer:
        def __init__(self, *args, **kwargs):
            server_calls.append((args, kwargs))
            self._address = (kwargs.get("host"), kwargs.get("port"))
        def start(self):
            return self
        @property
        def address(self):
            return self._address
    p2p.NodeServer = FakeNodeServer
    try:
        core = object.__new__(AxvenCore)
        core.chain = object()
        core.mempool = object()
        core.p2p_server = None
        assert core.start_p2p("127.0.0.1", 0) == ("127.0.0.1", 0)
        assert server_calls[-1][1]["port"] == 0
        checks += 1
        print("[GREEN] ephemeral integer listener port preserved")

        for bad in ("0", True, 0.0):
            core.p2p_server = None
            before = len(server_calls)
            expect_value_error(
                lambda bad=bad: core.start_p2p("127.0.0.1", bad),
                f"listener port type {type(bad).__name__} rejected pre-bind",
            )
            assert len(server_calls) == before
            checks += 1

        core.p2p_server = None
        before = len(server_calls)
        expect_value_error(
            lambda: core.start_p2p("127.0.0.1", 65536),
            "oversized listener port rejected pre-bind",
        )
        assert len(server_calls) == before
        checks += 1
    finally:
        p2p.NodeServer = original_server

    source = Path(__file__).with_name("core.py").read_text(encoding="utf-8")
    assert "port=int(peer[1])" not in source
    assert "host=host, port=int(port)" not in source
    assert "type(value) is not int" in source
    checks += 1
    print("[GREEN] production structured/listener port coercion removed")

    assert checks == 28, checks
    print("SEC-144 peer port type domain: 28/28 GREEN")


if __name__ == "__main__":
    main()
