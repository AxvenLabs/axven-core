#!/usr/bin/env python3
"""SEC-071: bound and type-check P2P message dispatch names."""

import p2p


def expect_protocol_error(fn, contains):
    try:
        fn()
    except p2p.ProtocolError as exc:
        assert contains in str(exc), (contains, str(exc))
        return
    raise AssertionError(f"expected ProtocolError containing {contains!r}")


def main():
    checks = 0

    assert p2p.MAX_P2P_MESSAGE_TYPE_CHARS == 32
    checks += 1

    assert p2p._validate_message_type({"type": "get_status"}) == "get_status"
    checks += 1

    expect_protocol_error(
        lambda: p2p._validate_message_type({}),
        "message type must be string",
    )
    checks += 1

    for bad in (None, 1, True, 1.5, [], {}):
        expect_protocol_error(
            lambda value=bad: p2p._validate_message_type({"type": value}),
            "message type must be string",
        )
    checks += 1

    expect_protocol_error(
        lambda: p2p._validate_message_type(
            {"type": "x" * (p2p.MAX_P2P_MESSAGE_TYPE_CHARS + 1)}
        ),
        "message type too long",
    )
    checks += 1

    boundary = "x" * p2p.MAX_P2P_MESSAGE_TYPE_CHARS
    assert p2p._validate_message_type({"type": boundary}) == boundary
    checks += 1

    class TrapChain:
        def __getattribute__(self, name):
            if name.startswith("__"):
                return object.__getattribute__(self, name)
            raise AssertionError(f"chain touched before message type rejection: {name}")

    session = p2p.PeerSession(TrapChain(), None)
    expect_protocol_error(
        lambda: session.handle(
            {"type": "y" * (p2p.MAX_P2P_MESSAGE_TYPE_CHARS + 1)}
        ),
        "message type too long",
    )
    checks += 1

    assert session.handle({"type": "status"}) is None
    checks += 1

    assert checks == 8
    print("SEC-071 P2P message type bounds: 8/8 GREEN")


if __name__ == "__main__":
    main()
