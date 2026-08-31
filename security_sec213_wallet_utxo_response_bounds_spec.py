#!/usr/bin/env python3
"""SEC-213: wallet UTXO inspection must have bounded response cardinality."""
from __future__ import annotations

import json
from pathlib import Path

import axven
from core import AxvenCore
import rpc
import wallet


def _dust_core(count: int = 1105):
    chain = axven.Blockchain()
    identity = wallet.WalletIdentity()
    address = identity.address_n
    with chain._state_lock:
        for index in range(count):
            txid = f"{index + 1:064x}"
            chain.utxo[f"{txid}:0"] = {
                "amount": 1,
                "recipient": address,
                "coinbase": False,
                "height": 0,
            }
    return AxvenCore(chain=chain, mempool=axven.Mempool(chain), identity=identity)


def main() -> None:
    checks = 0
    core = _dust_core()

    source = Path("core.py").read_text(encoding="utf-8")
    rpc_source = Path("rpc.py").read_text(encoding="utf-8")
    cli_source = Path("axven_cli.py").read_text(encoding="utf-8")
    assert "MAX_LIST_UNSPENT_RESULTS = 1000" in source
    assert "list_unspent_page" in source
    assert '"list_unspent_page"' in rpc_source
    assert '"list-unspent-page"' in cli_source
    assert '"list_unspent_page"' in cli_source
    checks += 1
    print("[GREEN] wallet UTXO RPC surface has an explicit bounded paging contract")

    original_spendable = core.chain.spendable

    def forbidden_spendable(_address):
        raise AssertionError("SEC-213 wallet status/listing must not materialize chain.spendable()")

    core.chain.spendable = forbidden_spendable
    try:
        status = core.wallet_status(axven.SCHEME_ED25519)
        assert status["total"] == 1105
        assert status["spendable"] == 1105
        assert status["reserved"] == 0
        assert status["immature"] == 0
    finally:
        core.chain.spendable = original_spendable
    checks += 1
    print("[GREEN] wallet summary scans spendable state without an unbounded intermediate list")

    try:
        core.list_unspent(axven.SCHEME_ED25519)
    except ValueError as exc:
        assert "use list_unspent_page" in str(exc)
    else:
        raise AssertionError("legacy list_unspent must fail closed above its result budget")
    checks += 1
    print("[GREEN] legacy list_unspent refuses an oversized response instead of materializing it")

    first = core.list_unspent_page(axven.SCHEME_ED25519, offset=0, limit=100)
    assert first["offset"] == 0
    assert first["limit"] == 100
    assert len(first["utxos"]) == 100
    assert first["next_offset"] == 100
    second = core.list_unspent_page(axven.SCHEME_ED25519, offset=100, limit=100)
    assert len(second["utxos"]) == 100
    assert second["next_offset"] == 200
    tail = core.list_unspent_page(axven.SCHEME_ED25519, offset=1100, limit=100)
    assert len(tail["utxos"]) == 5
    assert tail["next_offset"] is None
    checks += 1
    print("[GREEN] bounded paging exposes large dusted wallets without oversized JSON results")

    for bad_offset in (-1, (1 << 31)):
        try:
            core.list_unspent_page(axven.SCHEME_ED25519, offset=bad_offset, limit=100)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid offset accepted: {bad_offset}")
    for bad_limit in (0, AxvenCore.MAX_LIST_UNSPENT_RESULTS + 1):
        try:
            core.list_unspent_page(axven.SCHEME_ED25519, offset=0, limit=bad_limit)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid limit accepted: {bad_limit}")
    checks += 1
    print("[GREEN] page offset and result-count budgets fail closed")

    dispatcher = rpc.RPCDispatcher(core)
    page = dispatcher.call(
        "list_unspent_page",
        {"scheme": axven.SCHEME_ED25519, "offset": 0, "limit": 64},
    )
    assert len(page["utxos"]) == 64
    assert page["next_offset"] == 64
    checks += 1
    print("[GREEN] RPC dispatcher exposes only the bounded UTXO paging method for large wallets")

    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "axven_cli.py",
        "core.py",
        "rpc.py",
        "security_sec213_wallet_utxo_response_bounds_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers SEC-213 service/RPC code and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-213 leaves canonical chain identity unchanged")

    print(f"SEC-213 wallet UTXO response bounds: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
