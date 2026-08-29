#!/usr/bin/env python3
"""SEC-150 persisted chain-state JSON preparse hardening contract."""

import tempfile
import axven


def _expect_value_error(label, fn, contains=None):
    try:
        fn()
    except ValueError as exc:
        if contains is not None:
            assert contains in str(exc), (label, str(exc))
        print(f"[GREEN] {label}")
        return 1
    raise AssertionError(f"{label}: expected ValueError")


def main():
    checks = 0
    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        chain = axven.Blockchain()
        store.persist(chain)
        loaded = store.load()
        assert loaded.tip.hash() == chain.tip.hash()
        assert loaded.chainwork == chain.chainwork
        checks += 1
        print("[GREEN] canonical chain-state roundtrip preserved")

    limit = axven.MAX_CHAIN_STATE_JSON_NESTING_DEPTH
    boundary = ("[" * limit + "0" + "]" * limit).encode("ascii")
    axven._preflight_chain_state_json(boundary)
    checks += 1
    print("[GREEN] exact chain-state nesting boundary accepted")

    checks += _expect_value_error(
        "over-depth chain-state JSON rejected before parsing",
        lambda: axven._preflight_chain_state_json(
            ("[" * (limit + 1) + "0" + "]" * (limit + 1)).encode("ascii")
        ),
        "nesting depth exceeded",
    )

    quoted = b'{"text":"[[[[{{{{\\\"still-string\\\"}}}}]]]]"}'
    axven._preflight_chain_state_json(quoted)
    checks += 1
    print("[GREEN] quote-aware preflight ignores structural bytes in strings")

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        raw = (
            '{"chain_id":"%s","chain_id":"%s",'
            '"config_fingerprint":"%s","blocks":[]}'
            % (axven.CHAIN_ID, axven.CHAIN_ID, axven.CONFIG_FINGERPRINT)
        ).encode("utf-8")
        store.path.write_bytes(raw)
        checks += _expect_value_error(
            "duplicate top-level chain-state key rejected",
            store.load,
            "duplicate chain state JSON key",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        raw = (
            '{"chain_id":"%s","config_fingerprint":"%s",'
            '"blocks":[{"height":0,"height":0}]}'
            % (axven.CHAIN_ID, axven.CONFIG_FINGERPRINT)
        ).encode("utf-8")
        store.path.write_bytes(raw)
        checks += _expect_value_error(
            "duplicate nested chain-state key rejected recursively",
            store.load,
            "duplicate chain state JSON key",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        store.path.write_bytes(b'{"chain_id":"' + b'\xff' + b'"}')
        checks += _expect_value_error(
            "invalid UTF-8 chain-state encoding fails closed",
            store.load,
            "encoding",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        store.path.write_bytes(b'{"chain_id":')
        checks += _expect_value_error(
            "malformed chain-state JSON fails closed",
            store.load,
            "invalid chain state JSON",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        store.path.write_bytes(b'[]')
        checks += _expect_value_error(
            "non-object chain-state envelope rejected",
            store.load,
            "chain state must be an object",
        )

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 10, checks
    print("SEC-150 chain-state JSON preparse: 10/10 GREEN")


if __name__ == "__main__":
    main()
