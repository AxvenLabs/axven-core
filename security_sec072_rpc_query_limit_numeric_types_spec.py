#!/usr/bin/env python3
"""SEC-072: RPC query limits require canonical JSON integers."""

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

    def recent_blocks(self, limit):
        self.calls.append(("recent", limit))
        return limit

    def mempool_view(self, limit):
        self.calls.append(("mempool", limit))
        return limit


def main():
    core = Core()
    d = rpc.RPCDispatcher(core)
    checks = 0

    for bad in ("20", 1.5, True, None, []):
        expect_error(
            lambda value=bad: d.call("get_recent_blocks", {"limit": value}),
            "recent blocks limit must be integer",
        )
        assert core.calls == []
    checks += 1

    for bad in ("100", 2.5, False, None, {}):
        expect_error(
            lambda value=bad: d.call("get_mempool", {"limit": value}),
            "mempool limit must be integer",
        )
        assert core.calls == []
    checks += 1

    assert d.call("get_recent_blocks", {"limit": 20}) == 20
    assert core.calls.pop() == ("recent", 20)
    checks += 1

    assert d.call("get_mempool", {"limit": 100}) == 100
    assert core.calls.pop() == ("mempool", 100)
    checks += 1

    assert d.call("get_recent_blocks") == 20
    assert core.calls.pop() == ("recent", 20)
    checks += 1

    assert d.call("get_mempool") == 100
    assert core.calls.pop() == ("mempool", 100)
    checks += 1

    assert checks == 6
    print("SEC-072 RPC query limit numeric types: 6/6 GREEN")


if __name__ == "__main__":
    main()
