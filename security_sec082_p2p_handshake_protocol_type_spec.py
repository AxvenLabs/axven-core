#!/usr/bin/env python3
# SEC-082 canonical P2P handshake protocol-version type contract.

import p2p


def expect_rejected(msg, label):
    try:
        p2p.validate_handshake(msg)
    except p2p.ProtocolError:
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def main():
    canonical = p2p.hello_message()
    assert type(canonical["protocol_version"]) is int
    assert canonical["protocol_version"] == p2p.PROTOCOL_VERSION == 2
    p2p.validate_handshake(dict(canonical))
    print("[GREEN] canonical integer protocol v2 handshake preserved")

    for bad, label in (
        (2.0, "float protocol version rejected"),
        ("2", "string protocol version rejected"),
        (True, "boolean protocol version rejected"),
        (None, "null protocol version rejected"),
    ):
        msg = dict(canonical)
        msg["protocol_version"] = bad
        expect_rejected(msg, label)

    msg = dict(canonical)
    msg["protocol_version"] = 3
    expect_rejected(msg, "different canonical integer protocol version still rejected")

    print("SEC-082 P2P handshake protocol version type: 6/6 GREEN")


if __name__ == "__main__":
    main()
