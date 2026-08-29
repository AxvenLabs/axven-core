#!/usr/bin/env python3
"""SEC-154 miner candidate byte-budget and legacy pool compatibility contract."""

import inspect

import axven


class LegacyRecordingPool:
    """Pool-like object intentionally exposing only the pre-SEC-154 API."""
    def __init__(self, selected=None):
        self.selected = list(selected or [])
        self.calls = 0

    def select(self):
        self.calls += 1
        return list(self.selected)


def sample_tx(recipient_chars):
    return axven.Transaction(
        [],
        [axven.TxOutput(1, "N" + ("a" * recipient_chars))],
    )


def main():
    checks = 0

    small = sample_tx(1)
    large = sample_tx(4096)
    small_wire = axven.serialized_transaction_size(small) + 1

    chosen = axven._fit_transactions_to_byte_budget(
        [large, small], small_wire
    )
    assert chosen == [small]
    checks += 1
    print("[GREEN] oversized leading candidate does not block smaller later candidate")

    assert axven._fit_transactions_to_byte_budget(
        [small], small_wire - 1
    ) == []
    assert axven._fit_transactions_to_byte_budget(
        [small], small_wire
    ) == [small]
    checks += 1
    print("[GREEN] transaction-array comma byte is included in miner budget")

    assert axven._fit_transactions_to_byte_budget([small], 0) == []
    checks += 1
    print("[GREEN] zero miner transaction byte budget fails closed")

    for bad in (-1, True, 1.5, "10", None):
        try:
            axven._fit_transactions_to_byte_budget([small], bad)
        except ValueError as exc:
            assert str(exc) == "invalid miner transaction byte budget"
        else:
            raise AssertionError(f"invalid byte budget accepted: {bad!r}")
    checks += 1
    print("[GREEN] miner byte budget has exact non-negative integer domain")

    # SEC-081 and external pool-like callers rely on select() with no new
    # keyword requirements.  This must remain source/API compatible.
    params = inspect.signature(axven.Mempool.select).parameters
    assert "byte_budget" not in params
    legacy = LegacyRecordingPool()
    chain = axven.Blockchain()
    wallet = axven.Wallet()
    block = chain.build_candidate(wallet.address, legacy)
    assert legacy.calls == 1
    checks += 1
    print("[GREEN] legacy no-keyword mempool select interface remains compatible")

    assert axven.block_size_valid(block)
    assert axven.serialized_block_size(block) <= 7 * 1024 * 1024
    checks += 1
    print("[GREEN] locally built candidate obeys canonical block byte limit")

    ok, status = chain.add_block(block)
    assert ok and status == "extended"
    checks += 1
    print("[GREEN] byte-budgeted self-built candidate is accepted by consensus")

    build_src = inspect.getsource(axven.Blockchain._build_candidate_locked)
    helper_src = inspect.getsource(axven._fit_transactions_to_byte_budget)
    assert "mempool.select()" in build_src
    assert "mempool.select(byte_budget=" not in build_src
    assert "_fit_transactions_to_byte_budget" in build_src
    assert "serialized_block_size(sizing_block)" in build_src
    assert "wire_bytes = serialized_transaction_size(tx) + 1" in helper_src
    assert "if not block_size_valid(block)" in build_src
    checks += 1
    print("[GREEN] production miner keeps byte-aware filtering without API expansion")

    assert axven.CHAIN_CONFIG["max_block_bytes"] == 7 * 1024 * 1024
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] consensus block limit and canonical chain identity unchanged")

    assert checks == 9, checks
    print("SEC-154 miner candidate byte budget: 9/9 GREEN")


if __name__ == "__main__":
    main()
