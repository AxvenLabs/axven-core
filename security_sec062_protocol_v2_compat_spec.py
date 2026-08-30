#!/usr/bin/env python3
"""SEC-062 network compatibility boundary; advanced to v3 by SEC-196."""

import copy

import axven
import p2p


EXPECTED_PROTOCOL_VERSION = 3


def expect_protocol_error(message, label):
    try:
        p2p.validate_handshake(message)
    except p2p.ProtocolError as exc:
        if "protocol_version mismatch" not in str(exc):
            raise AssertionError(
                f"{label}: unexpected ProtocolError: {exc}"
            ) from exc
        print(f"[GREEN] {label}")
        return

    raise AssertionError(label)


def main():
    checks = 0

    # SEC-062 is a network compatibility boundary.
    assert p2p.PROTOCOL_VERSION == EXPECTED_PROTOCOL_VERSION, (
        f"protocol version must be {EXPECTED_PROTOCOL_VERSION}, "
        f"got {p2p.PROTOCOL_VERSION}"
    )
    checks += 1
    print("[GREEN] protocol version pinned to v3")

    identity = p2p.local_identity()

    assert identity["protocol_version"] == EXPECTED_PROTOCOL_VERSION
    checks += 1
    print("[GREEN] local identity advertises protocol v3")

    # Existing network identity remains unchanged.
    assert identity["chain_id"] == axven.CHAIN_ID
    assert identity["config_fingerprint"] == axven.CONFIG_FINGERPRINT
    assert identity["genesis_hash"] == axven._genesis().hash()
    checks += 1
    print("[GREEN] chain/fingerprint/genesis identity preserved")

    # Same-version peer remains valid.
    good = {
        "type": "hello",
        **identity,
    }
    p2p.validate_handshake(good)
    checks += 1
    print("[GREEN] v3 peer accepted")

    # SEC-062-predecessor nodes must not join the v2 network.
    old = copy.deepcopy(good)
    old["protocol_version"] = 2
    expect_protocol_error(
        old,
        "legacy protocol v2 peer rejected",
    )
    checks += 1

    # Unknown future versions must also fail closed.
    future = copy.deepcopy(good)
    future["protocol_version"] = 4
    expect_protocol_error(
        future,
        "unknown protocol v4 peer rejected",
    )
    checks += 1

    print(
        f"SEC-062 protocol-v3 compatibility boundary: "
        f"{checks}/6 GREEN"
    )


if __name__ == "__main__":
    main()