#!/usr/bin/env python3
"""SEC-143 exact peer/listener host type-domain regression contract."""

from core import AxvenCore
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
    print("[GREEN] canonical tuple peer preserved")

    assert AxvenCore._parse_peer(["node.axven.org", 31337]) == ("node.axven.org", 31337)
    checks += 1
    print("[GREEN] canonical list peer preserved")

    assert AxvenCore._parse_peer("node.axven.org:31337") == ("node.axven.org", 31337)
    checks += 1
    print("[GREEN] canonical scalar peer preserved")

    assert AxvenCore._parse_peer(("  node.axven.org  ", 31337)) == ("node.axven.org", 31337)
    checks += 1
    print("[GREEN] peer host whitespace normalization preserved")

    maximum = "a" * 255
    assert AxvenCore._parse_peer((maximum, 31337)) == (maximum, 31337)
    checks += 1
    print("[GREEN] maximum peer host preserved")

    for bad in ([], {}, True, 7, b"node.axven.org", None):
        expect_value_error(
            lambda bad=bad: AxvenCore._parse_peer((bad, 31337)),
            f"structured peer host type {type(bad).__name__} rejected",
        )
        checks += 1

    class Sneaky:
        called = False
        def __str__(self):
            self.called = True
            return "node.axven.org:31337"

    sneaky = Sneaky()
    expect_value_error(lambda: AxvenCore._parse_peer(sneaky), "scalar peer object rejected")
    assert not sneaky.called
    checks += 1
    print("[GREEN] scalar peer rejected without __str__ coercion")

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
        before = len(sync_calls)
        expect_value_error(lambda: core.sync_peer({"host": "127.0.0.1"}, 31337, 1), "sync_peer dict host rejected pre-I/O")
        assert len(sync_calls) == before
        checks += 1

        before = len(sync_calls)
        expect_value_error(lambda: core.sync_peer(True, 31337, 1), "sync_peer bool host rejected pre-I/O")
        assert len(sync_calls) == before
        checks += 1
    finally:
        p2p.sync_to_peer = original_sync

    original_server = p2p.NodeServer
    server_calls = []
    class FakeNodeServer:
        def __init__(self, *args, **kwargs):
            server_calls.append((args, kwargs))
        def start(self):
            return self
        @property
        def address(self):
            return ("127.0.0.1", 0)
    p2p.NodeServer = FakeNodeServer
    try:
        core = object.__new__(AxvenCore)
        core.chain = object()
        core.mempool = object()
        core.p2p_server = None
        before = len(server_calls)
        expect_value_error(lambda: core.start_p2p(["127.0.0.1"], 0), "listener list host rejected pre-bind")
        assert len(server_calls) == before
        checks += 1

        before = len(server_calls)
        expect_value_error(lambda: core.start_p2p(False, 0), "listener bool host rejected pre-bind")
        assert len(server_calls) == before
        checks += 1
    finally:
        p2p.NodeServer = original_server

    assert checks == 16
    print("SEC-143 peer host type domain: 16/16 GREEN")


if __name__ == "__main__":
    main()
