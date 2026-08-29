#!/usr/bin/env python3
"""SEC-138 validates block lookup ids before chain-state lock acquisition."""

import inspect

import axven
import core as core_module


class ProbeLock:
    def __init__(self):
        self.entries=0

    def __enter__(self):
        self.entries+=1
        return self

    def __exit__(self,exc_type,exc,tb):
        return False


class FakeChain:
    def __init__(self):
        self._state_lock=ProbeLock()
        self.blocks=[]
        self.index={}


def make_core():
    service=object.__new__(core_module.AxvenCore)
    service.chain=FakeChain()
    return service


def expect_prelock_reject(service,value,label,message=None):
    before=service.chain._state_lock.entries
    try:
        service.get_block(value)
    except ValueError as exc:
        ok=(message is None or str(exc)==message)
    else:
        ok=False
    assert ok and service.chain._state_lock.entries==before,label
    print("[GREEN]",label)


def expect_normal_miss(service,value,label):
    before=service.chain._state_lock.entries
    try:
        service.get_block(value)
    except KeyError:
        ok=True
    else:
        ok=False
    assert ok and service.chain._state_lock.entries==before+1,label
    print("[GREEN]",label)


def main():
    checks=0
    service=make_core()

    rejects=(
        (["a"*64],"list block id rejected before state lock"),
        ({"id":"a"*64},"object block id rejected before state lock"),
        (None,"null block id rejected before state lock"),
        (True,"boolean block id rejected before state lock"),
        (1.0,"float block id rejected before state lock"),
    )
    for value,label in rejects:
        expect_prelock_reject(service,value,label)
        checks+=1

    expect_prelock_reject(
        service,"z"*65,"oversized block string rejected before state lock",
        "block id too long",
    ); checks+=1
    expect_prelock_reject(
        service,"z"*1_000_000,"extreme block string rejected before state lock",
        "block id too long",
    ); checks+=1

    # Preserve the exact legacy lookup domain protected by SEC-053/SEC-056.
    expect_normal_miss(
        service,"z"*64,"maximum non-numeric block string still reaches normal lookup",
    ); checks+=1
    expect_normal_miss(
        service,"100","bounded numeric block string still reaches normal lookup",
    ); checks+=1
    expect_normal_miss(
        service,0,"built-in integer block height still reaches normal lookup",
    ); checks+=1

    try:
        service._get_block_locked(False)
    except ValueError:
        direct_guard=True
    else:
        direct_guard=False
    assert direct_guard,"locked helper independently rejects coercion aliases"
    print("[GREEN] locked helper independently rejects coercion aliases"); checks+=1

    public_src=inspect.getsource(core_module.AxvenCore.get_block)
    validator_src=inspect.getsource(core_module.AxvenCore._validate_block_id)
    assert (
        public_src.index("_validate_block_id")
        < public_src.index("with self.chain._state_lock")
    ),"production validates block id before chain state lock"
    print("[GREEN] production validates block id before chain state lock"); checks+=1

    assert (
        "type(block_id) is int" in validator_src
        and "type(block_id) is not str" in validator_src
        and "len(block_id) > 64" in validator_src
    ),"block id domain is exact built-in int or bounded string"
    print("[GREEN] block id domain is exact built-in int or bounded string"); checks+=1

    assert (
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    ),"block id hardening leaves canonical chain identity unchanged"
    print("[GREEN] block id hardening leaves canonical chain identity unchanged"); checks+=1

    print(f"SEC-138 block id pre-lock domain: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
