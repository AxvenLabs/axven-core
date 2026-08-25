#!/usr/bin/env python3
"""SEC-062 canonical block miner consensus contract."""

import copy

import axven


def remine(block):
    block.nonce = 0
    while not block.pow_ok():
        block.nonce += 1


def fresh_candidate():
    chain = axven.Blockchain()
    wallet = axven.Wallet()
    block = chain.build_candidate(wallet.address)
    return chain, wallet, block


def set_coinbase_recipient(chain, block, recipient):
    # Contract fixtures use an otherwise-empty height-1 candidate.
    assert len(block.transactions) == 1

    block.transactions[0]["outputs"][0]["recipient"] = recipient

    txs = [axven.Transaction.from_dict(t) for t in block.transactions]
    block.merkle_root = axven.merkle_root([t.txid() for t in txs])

    # Rebuild the expected post-block state without depending on
    # production validation accepting the malformed address.
    trial = copy.deepcopy(chain.utxo)
    coinbase = txs[0]
    output = coinbase.outputs[0]
    trial[axven.outpoint(coinbase.txid(), 0)] = {
        "amount": output.amount,
        "recipient": recipient,
        "coinbase": True,
        "height": block.height,
    }

    block.utxo_state_root = axven.expected_state_root(trial, block.height)
    remine(block)


def expect_reject(chain, block, label):
    ok, status = chain.add_block(block)
    if ok:
        raise AssertionError(
            f"{label}: consensus accepted malformed miner "
            f"(status={status!r})"
        )

    if "miner" not in str(status).lower():
        raise AssertionError(
            f"{label}: rejected for unexpected reason: {status!r}"
        )

    print(f"[GREEN] {label}")


def main():
    checks = 0

    # Existing genesis identity is explicitly outside the new non-genesis rule.
    genesis = axven._genesis()
    assert genesis.miner == axven.GENESIS_MINER
    assert len(genesis.miner) == 87
    checks += 1
    print("[GREEN] existing genesis miner identity preserved")

    # Canonical N + 40 lowercase hex address must remain consensus-valid.
    chain, wallet, block = fresh_candidate()
    assert len(wallet.address) == 41
    assert block.miner == wallet.address
    ok, status = chain.add_block(block)
    assert ok and status == "extended"
    checks += 1
    print("[GREEN] canonical 41-character miner preserved")

    # JSON structures must never be valid header miner identities.
    chain, wallet, block = fresh_candidate()
    block.miner = {}
    remine(block)
    expect_reject(chain, block, "dictionary miner rejected")
    checks += 1

    chain, wallet, block = fresh_candidate()
    block.miner = []
    remine(block)
    expect_reject(chain, block, "list miner rejected")
    checks += 1

    # Miner and coinbase recipient agree, but the address is non-canonical.
    chain, wallet, block = fresh_candidate()
    oversized = "N" + ("a" * 41)  # 42 chars
    block.miner = oversized
    set_coinbase_recipient(chain, block, oversized)
    expect_reject(chain, block, "oversized miner address rejected")
    checks += 1

    chain, wallet, block = fresh_candidate()
    non_hex = "N" + ("g" * 40)
    block.miner = non_hex
    set_coinbase_recipient(chain, block, non_hex)
    expect_reject(chain, block, "non-hex miner address rejected")
    checks += 1

    # Even two individually canonical addresses may not disagree.
    chain, wallet, block = fresh_candidate()
    other = axven.Wallet().address
    assert other != wallet.address
    block.miner = other
    remine(block)
    expect_reject(chain, block, "miner and coinbase recipient mismatch rejected")
    checks += 1

    # Extreme but still sub-block-limit miner/coinbase identity.
    chain, wallet, block = fresh_candidate()
    extreme = "N" + ("a" * 9_999)
    block.miner = extreme
    set_coinbase_recipient(chain, block, extreme)
    expect_reject(chain, block, "extreme miner address rejected")
    checks += 1

    print(f"SEC-062 canonical miner consensus contract: {checks}/8 GREEN")


if __name__ == "__main__":
    main()