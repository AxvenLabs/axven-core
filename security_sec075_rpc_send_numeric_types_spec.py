#!/usr/bin/env python3
"""SEC-075: RPC send amount/fee require canonical JSON integers."""

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

    def send(self, input_scheme, recipient, amount, fee):
        self.calls.append((input_scheme, recipient, amount, fee))
        return "txid"


def params(amount=1, fee=0):
    return {
        "input_scheme": "ed25519",
        "recipient": "axv-test",
        "amount": amount,
        "fee": fee,
    }


def main():
    core = Core()
    d = rpc.RPCDispatcher(core)
    checks = 0

    for bad in ("1", 1.0, True, None, []):
        expect_error(
            lambda value=bad: d.call("send", params(amount=value)),
            "send amount must be integer",
        )
        assert core.calls == []
    checks += 1

    for bad in ("0", 0.0, False, None, {}):
        expect_error(
            lambda value=bad: d.call("send", params(fee=value)),
            "send fee must be integer",
        )
        assert core.calls == []
    checks += 1

    assert d.call("send", params(1, 0)) == "txid"
    assert core.calls.pop() == ("ed25519", "axv-test", 1, 0)
    checks += 1

    max_value = (1 << 63) - 1
    assert d.call("send", params(max_value, max_value)) == "txid"
    assert core.calls.pop() == ("ed25519", "axv-test", max_value, max_value)
    checks += 1

    assert checks == 4
    print("SEC-075 RPC send numeric types: 4/4 GREEN")


if __name__ == "__main__":
    main()
