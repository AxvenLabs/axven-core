#!/usr/bin/env python3
"""SEC-182: wallet sends require canonical recipient addresses."""

import axven
from core import AxvenCore


def _expect_reject(value):
    try:
        AxvenCore._validate_recipient_bound(value)
    except ValueError:
        return
    raise AssertionError(f"non-canonical recipient accepted: {value!r}")


def main():
    canonical = [
        "N" + "0" * 40,
        "M" + "1" * 40,
        "H" + "abcdef0123" * 4,
    ]
    for address in canonical:
        assert AxvenCore._validate_recipient_bound(address) == address
    print("[GREEN] canonical N/M/H recipient forms accepted")

    malformed = [
        None,
        True,
        1,
        b"N" + b"0" * 40,
        "",
        "N",
        "N" + "0" * 39,
        "N" + "0" * 41,
        "X" + "0" * 40,
        "n" + "0" * 40,
        "N" + "A" * 40,
        "N" + "g" * 40,
        "N" + "0" * 39 + " ",
        "M" + "0" * 39 + "-",
        "H" + "0" * 39 + "\n",
    ]
    for value in malformed:
        _expect_reject(value)
    print("[GREEN] malformed recipient aliases rejected")

    # The consensus-era scheme classifier remains intentionally unchanged;
    # SEC-182 is a wallet/service safety boundary, not a block-validity fork.
    assert axven.output_scheme_allowed("Nbad", 1) is True
    assert axven.output_scheme_allowed("Mbad", 2500) is True
    print("[GREEN] consensus scheme-classification semantics unchanged")

    core = AxvenCore(identity=None)
    before_txs = dict(core.mempool.txs)
    try:
        core.send(axven.SCHEME_ED25519, "Nbad", 1, 0)
    except ValueError as exc:
        assert "recipient" in str(exc).lower()
    else:
        raise AssertionError("send accepted malformed recipient")
    assert core.mempool.txs == before_txs
    print("[GREEN] malformed send rejected before wallet/mempool mutation")

    try:
        core.send(axven.SCHEME_ED25519, canonical[0], 1, 0)
    except RuntimeError as exc:
        assert "wallet not loaded" in str(exc)
    else:
        raise AssertionError("canonical recipient did not reach wallet boundary")
    print("[GREEN] canonical recipient preserves downstream send semantics")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    print("[GREEN] canonical chain identity unchanged")

    print("SEC-182 wallet recipient canonicality: 6/6 GREEN")


if __name__ == "__main__":
    main()
