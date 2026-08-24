#!/usr/bin/env python3
"""SEC-051 P2P listener host bounds regression contract."""

from core import AxvenCore
import p2p


def main():
    original = p2p.NodeServer
    calls = []

    class FakeNodeServer:
        def __init__(self, chain, mempool, host="127.0.0.1", port=0):
            calls.append((host, port))
            self.host = host
            self.port = port

        def start(self):
            return self

        @property
        def address(self):
            return (self.host, self.port)

    p2p.NodeServer = FakeNodeServer

    try:
        def fresh_core():
            core = AxvenCore()
            core.p2p_server = None
            return core

        core = fresh_core()
        result = core.start_p2p("127.0.0.1", 0)
        assert result == ("127.0.0.1", 0)
        assert calls[-1] == ("127.0.0.1", 0)
        print("[GREEN] canonical P2P listener host preserved")

        core = fresh_core()
        result = core.start_p2p("0.0.0.0", 0)
        assert result == ("0.0.0.0", 0)
        assert calls[-1] == ("0.0.0.0", 0)
        print("[GREEN] public P2P listener host preserved")

        core = fresh_core()
        result = core.start_p2p("node.axven.org", 0)
        assert result == ("node.axven.org", 0)
        assert calls[-1] == ("node.axven.org", 0)
        print("[GREEN] DNS-style P2P listener host preserved")

        maximum = "a" * 255
        core = fresh_core()
        result = core.start_p2p(maximum, 0)
        assert result == (maximum, 0)
        assert calls[-1] == (maximum, 0)
        print("[GREEN] maximum P2P listener host length preserved")

        before = len(calls)
        core = fresh_core()

        try:
            core.start_p2p("a" * 256, 0)
        except ValueError as exc:
            assert str(exc) == "P2P listener host too long"
        else:
            raise AssertionError("oversized P2P listener host accepted")

        assert len(calls) == before
        print("[GREEN] oversized P2P listener host rejected before bind")

        print("SEC-051 P2P listener host bounds: 5/5 GREEN")

    finally:
        p2p.NodeServer = original


if __name__ == "__main__":
    main()
