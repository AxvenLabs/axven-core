#!/usr/bin/env python3
"""SEC-139 removes redundant O(UTXO) Explorer summary root recomputation."""

import inspect

import axven
import core as core_module


def main():
    checks=[]

    def green(name,condition):
        assert condition,name
        checks.append(name)
        print("[GREEN]",name)

    service=core_module.AxvenCore()
    canonical_tip_root=service.chain.tip.utxo_state_root
    green(
        "active tip committed root matches the canonical state-root oracle",
        canonical_tip_root
        == axven.expected_state_root(service.chain.utxo,service.chain.tip.height),
    )

    original=axven.expected_state_root
    calls=[]
    def forbidden_recompute(*args,**kwargs):
        calls.append((args,kwargs))
        raise AssertionError("Explorer summary attempted full state-root recomputation")

    axven.expected_state_root=forbidden_recompute
    try:
        summary=service.explorer_summary()
    finally:
        axven.expected_state_root=original

    green(
        "Explorer summary serves committed tip root without recomputation",
        summary["state_root"] == canonical_tip_root and calls == [],
    )
    green(
        "Explorer summary still exposes coherent tip identity",
        summary["height"] == service.chain.tip.height
        and summary["tip_hash"] == service.chain.tip.hash()
        and summary["latest_blocks"][0]["utxo_state_root"] == canonical_tip_root,
    )

    # The committed root is read while the existing SEC-014 state lock is
    # held, so a reorg cannot mix a tip from one state with a root from another.
    src=inspect.getsource(core_module.AxvenCore.explorer_summary)
    green(
        "committed root read remains inside the atomic chain-state boundary",
        src.index("with self.chain._state_lock")
        < src.index("self.chain.tip.utxo_state_root"),
    )
    green(
        "production Explorer summary contains no state-root recomputation",
        "expected_state_root" not in src
        and "self.chain.utxo" not in src
        and "self.chain.tip.utxo_state_root" in src,
    )

    # Prove the endpoint is independent from traversing the live UTXO mapping.
    class PoisonUTXO(dict):
        def __iter__(self):
            raise AssertionError("UTXO iteration is forbidden in Explorer summary")
        def items(self):
            raise AssertionError("UTXO items traversal is forbidden in Explorer summary")
        def values(self):
            raise AssertionError("UTXO values traversal is forbidden in Explorer summary")

    original_utxo=service.chain.utxo
    service.chain.utxo=PoisonUTXO(original_utxo)
    try:
        poison_summary=service.explorer_summary()
    finally:
        service.chain.utxo=original_utxo
    green(
        "Explorer summary performs no live UTXO traversal",
        poison_summary["state_root"] == canonical_tip_root,
    )

    green(
        "Explorer root hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-139 Explorer summary root work: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
