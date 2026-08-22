#!/usr/bin/env python3
"""SEC-043: bound RPC send amount and fee values."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_SEND_VALUE = (1 << 63) - 1


class DummyCore:
    def __init__(self):
        self.calls = []

    def send(self, input_scheme, recipient, amount, fee):
        self.calls.append((input_scheme, recipient, amount, fee))
        return {"ok": True}


def expect_error(dispatcher, params, expected):
    try:
        dispatcher.call("send", params)
    except RPCError as e:
        assert str(e) == expected, (
            f"unexpected RPC error for {params!r}: {e}"
        )
    else:
        raise AssertionError(
            f"RPC accepted invalid send parameters: {params!r}"
        )


def main():
    core = DummyCore()
    dispatcher = RPCDispatcher(core)

    base = {
        "input_scheme": "N",
        "recipient": "Nrecipient",
        "amount": 1000,
        "fee": 100,
    }

    # Canonical positive amount and non-negative fee must pass.
    result = dispatcher.call("send", dict(base))
    assert result == {"ok": True}
    assert core.calls[-1][2:] == (1000, 100)
    print("[GREEN] canonical RPC send values preserved")

    # Zero fee is valid and must reach normal dispatch.
    zero_fee = dict(base)
    zero_fee["fee"] = 0
    dispatcher.call("send", zero_fee)
    assert core.calls[-1][2:] == (1000, 0)
    print("[GREEN] zero RPC send fee preserved")

    # Amount must be strictly positive.
    before = len(core.calls)
    expect_error(
        dispatcher,
        {**base, "amount": 0},
        "invalid send amount",
    )
    expect_error(
        dispatcher,
        {**base, "amount": -1},
        "invalid send amount",
    )
    assert len(core.calls) == before
    print("[GREEN] non-positive RPC send amounts rejected")

    # Fee must not be negative.
    before = len(core.calls)
    expect_error(
        dispatcher,
        {**base, "fee": -1},
        "invalid send fee",
    )
    assert len(core.calls) == before
    print("[GREEN] negative RPC send fee rejected")

    # Maximum bounded integer values must still dispatch.
    maximum = dict(base)
    maximum["amount"] = MAX_RPC_SEND_VALUE
    maximum["fee"] = MAX_RPC_SEND_VALUE
    dispatcher.call("send", maximum)
    assert core.calls[-1][2:] == (
        MAX_RPC_SEND_VALUE,
        MAX_RPC_SEND_VALUE,
    )
    print("[GREEN] maximum RPC send values reach normal dispatch")

    # Values above the bound must be rejected before Core.
    before = len(core.calls)
    expect_error(
        dispatcher,
        {**base, "amount": MAX_RPC_SEND_VALUE + 1},
        "invalid send amount",
    )
    expect_error(
        dispatcher,
        {**base, "fee": MAX_RPC_SEND_VALUE + 1},
        "invalid send fee",
    )
    assert len(core.calls) == before
    print("[GREEN] oversized RPC send values rejected")

    print("SEC-043 RPC send value bounds: 6/6 GREEN")


if __name__ == "__main__":
    main()
