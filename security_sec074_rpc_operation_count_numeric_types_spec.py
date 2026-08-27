#!/usr/bin/env python3
"""SEC-074: RPC mine/sync counts require canonical JSON integers."""

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

    def mine(self, count, scheme):
        self.calls.append(("mine", count, scheme))
        return count

    def sync_peer(self, host, port, batch):
        self.calls.append(("sync", host, port, batch))
        return batch


def main():
    core = Core()
    d = rpc.RPCDispatcher(core)
    checks = 0

    for bad in ("1", 1.0, True, None, []):
        expect_error(
            lambda value=bad: d.call("mine", {"count": value}),
            "mine count must be integer",
        )
        assert core.calls == []
    checks += 1

    for bad in ("128", 1.5, False, None, {}):
        expect_error(
            lambda value=bad: d.call(
                "sync_peer",
                {"host": "127.0.0.1", "port": 18444, "batch": value},
            ),
            "sync batch must be integer",
        )
        assert core.calls == []
    checks += 1

    assert d.call("mine", {"count": 1}) == 1
    assert core.calls.pop() == ("mine", 1, None)
    checks += 1

    assert d.call("mine") == 1
    assert core.calls.pop() == ("mine", 1, None)
    checks += 1

    assert d.call("sync_peer", {"host": "127.0.0.1", "port": 18444, "batch": 128}) == {"accepted": 128}
    assert core.calls.pop() == ("sync", "127.0.0.1", 18444, 128)
    checks += 1

    assert checks == 5
    print("SEC-074 RPC operation count numeric types: 5/5 GREEN")


if __name__ == "__main__":
    main()
