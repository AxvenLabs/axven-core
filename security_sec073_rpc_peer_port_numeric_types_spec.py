#!/usr/bin/env python3
"""SEC-073: RPC peer ports require canonical JSON integers."""

import rpc


def expect_error(fn, text):
    try:
        fn()
    except rpc.RPCError as exc:
        assert text in str(exc), (text, str(exc))
        return
    raise AssertionError(f"expected RPCError containing {text!r}")


class Core:
    def __init__(self):
        self.calls = []

    def add_outbound_peer(self, peer):
        self.calls.append(("add", peer))
        return peer

    def remove_outbound_peer(self, peer):
        self.calls.append(("remove", peer))
        return True

    def start_p2p(self, host, port):
        self.calls.append(("start", host, port))
        return host, port

    def sync_peer(self, host, port, batch):
        self.calls.append(("sync", host, port, batch))
        return 0


def main():
    core = Core()
    d = rpc.RPCDispatcher(core)
    checks = 0

    routes = (
        ("add_peer", {"host": "127.0.0.1", "port": "18444"}, "peer port must be integer"),
        ("remove_peer", {"host": "127.0.0.1", "port": True}, "peer port must be integer"),
        ("start_p2p", {"host": "127.0.0.1", "port": 1.5}, "start_p2p port must be integer"),
        ("sync_peer", {"host": "127.0.0.1", "port": "18444", "batch": 1}, "sync peer port must be integer"),
    )
    for method, params, text in routes:
        expect_error(lambda m=method, p=params: d.call(m, p), text)
        assert core.calls == []
    checks += 1

    assert d.call("add_peer", {"host": "127.0.0.1", "port": 18444})["port"] == 18444
    assert core.calls.pop() == ("add", ("127.0.0.1", 18444))
    checks += 1

    assert d.call("remove_peer", {"host": "127.0.0.1", "port": 18444}) is True
    assert core.calls.pop() == ("remove", ("127.0.0.1", 18444))
    checks += 1

    assert d.call("start_p2p", {"host": "127.0.0.1", "port": 0})["port"] == 0
    assert core.calls.pop() == ("start", "127.0.0.1", 0)
    checks += 1

    assert d.call("sync_peer", {"host": "127.0.0.1", "port": 18444, "batch": 1}) == {"accepted": 0}
    assert core.calls.pop() == ("sync", "127.0.0.1", 18444, 1)
    checks += 1

    assert checks == 5
    print("SEC-073 RPC peer port numeric types: 5/5 GREEN")


if __name__ == "__main__":
    main()
