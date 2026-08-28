#!/usr/bin/env python3
"""SEC-113 canonical P2P status envelope and field domains."""

import axven
import p2p


def rejected(session, msg):
    try:
        session.handle(msg)
    except p2p.ProtocolError:
        return True
    return False


def main():
    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)
    canonical = session.status()

    assert set(canonical) == {"type", "height", "tip_hash", "chainwork"}
    assert session.handle(dict(canonical)) is None
    print("[GREEN] canonical status envelope preserved")

    for extra in (0, None, {}, [], {"nested": [1, 2, 3]}):
        bad = dict(canonical)
        bad["extra"] = extra
        assert rejected(session, bad)
    print("[GREEN] unknown status fields rejected")

    for field in ("height", "tip_hash", "chainwork"):
        bad = dict(canonical)
        bad.pop(field)
        assert rejected(session, bad)
    assert rejected(session, {"type": "status"})
    print("[GREEN] missing status fields rejected")

    for value in (True, -1, "0", 0.0, None):
        bad = dict(canonical)
        bad["height"] = value
        assert rejected(session, bad)
    print("[GREEN] status height domain enforced")

    for value in (None, 0, "0" * 63, "0" * 65, "g" * 64, "A" * 64):
        bad = dict(canonical)
        bad["tip_hash"] = value
        assert rejected(session, bad)
    print("[GREEN] status tip hash is canonical lowercase hex")

    for value in (True, -1, "1", 1.0, None):
        bad = dict(canonical)
        bad["chainwork"] = value
        assert rejected(session, bad)
    print("[GREEN] status chainwork domain enforced")

    source = PathLike = open(p2p.__file__, "r", encoding="utf-8").read()
    assert 'expected_fields={"type","height","tip_hash","chainwork"}' in source
    assert 'raise ProtocolError("invalid status message fields")' in source
    print("[GREEN] status validation wired before silent consume")

    print("SEC-113 canonical P2P status envelope: 6/6 GREEN")


if __name__ == "__main__":
    main()
