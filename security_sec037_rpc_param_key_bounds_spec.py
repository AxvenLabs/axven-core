#!/usr/bin/env python3

import rpc


class DummyCore:
    def status(self):
        return {"ok": True}


def expect_rpc_error(dispatcher, params, expected):
    try:
        dispatcher.call("get_status", params)
    except rpc.RPCError as e:
        assert str(e) == expected, (
            f"unexpected RPC error for params {params!r}: {e}"
        )
        return

    raise AssertionError(
        f"RPC accepted invalid parameter key: {params!r}"
    )


def main():
    dispatcher = rpc.RPCDispatcher(DummyCore())

    result = dispatcher.call("get_status", {"normal_key": 1})
    assert result == {"ok": True}
    print("[GREEN] canonical RPC parameter key preserved")

    expect_rpc_error(
        dispatcher,
        {1: "value"},
        "invalid param key",
    )
    print("[GREEN] non-string RPC parameter key rejected")

    expect_rpc_error(
        dispatcher,
        {"": "value"},
        "invalid param key",
    )
    print("[GREEN] empty RPC parameter key rejected")

    oversized = "k" * 257
    expect_rpc_error(
        dispatcher,
        {oversized: "value"},
        "invalid param key",
    )
    print("[GREEN] oversized RPC parameter key rejected")

    boundary = "k" * 256

    try:
        dispatcher.call(
            "__sec037_unknown_method__",
            {boundary: "value"},
        )
    except rpc.RPCError as e:
        assert str(e) == "unknown method", (
            "maximum-length valid parameter key did not reach "
            f"normal dispatch: {e}"
        )
    else:
        raise AssertionError(
            "SEC-037 boundary probe unexpectedly dispatched"
        )

    print("[GREEN] maximum RPC parameter key length reaches normal dispatch")
    print("SEC-037 RPC parameter key bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
