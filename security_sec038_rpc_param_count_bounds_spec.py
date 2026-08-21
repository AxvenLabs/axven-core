#!/usr/bin/env python3
"""SEC-038: bound the number of RPC parameter keys."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_PARAMS = 64


class DummyCore:
    def status(self):
        return {"ok": True}


def main():
    dispatcher = RPCDispatcher(DummyCore())

    # Normal canonical request must remain valid.
    result = dispatcher.call("get_status", {"scheme": "N"})
    assert result == {"ok": True}
    print("[GREEN] canonical RPC parameter count preserved")

    # Exactly the maximum number of parameters must pass structural
    # validation and reach normal method dispatch.
    maximum = {f"k{i}": i for i in range(MAX_RPC_PARAMS)}
    try:
        dispatcher.call("unknown_method", maximum)
    except RPCError as e:
        assert str(e) == "unknown method", (
            f"maximum valid RPC parameter count did not reach dispatch: {e}"
        )
    else:
        raise AssertionError("unknown method unexpectedly succeeded")
    print("[GREEN] maximum RPC parameter count reaches normal dispatch")

    # One parameter beyond the bound must be rejected before dispatch.
    oversized = {f"k{i}": i for i in range(MAX_RPC_PARAMS + 1)}
    try:
        dispatcher.call("unknown_method", oversized)
    except RPCError as e:
        assert str(e) == "too many params", (
            f"unexpected RPC error for oversized params: {e}"
        )
    else:
        raise AssertionError(
            f"RPC accepted {len(oversized)} parameters; expected bound {MAX_RPC_PARAMS}"
        )
    print("[GREEN] oversized RPC parameter count rejected")

    print("SEC-038 RPC parameter count bounds: 3/3 GREEN")


if __name__ == "__main__":
    main()
