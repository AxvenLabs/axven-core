#!/usr/bin/env python3
"""SEC-140 enforces an exact textual scheme-selector domain."""

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


def make_core():
    service=object.__new__(core_module.AxvenCore)
    service.chain=FakeChain()
    return service


def expect_value_error(call,label,message="scheme must be string"):
    try:
        call()
    except ValueError as exc:
        ok=str(exc)==message
    else:
        ok=False
    assert ok,label
    print("[GREEN]",label)


def main():
    checks=0
    service=make_core()

    # Each public scheme-taking surface must fail before wallet, lock, mining,
    # transaction construction, or other downstream work becomes reachable.
    expect_value_error(
        lambda: service.balance([]),
        "list balance scheme rejected before wallet work",
    ); checks+=1

    before=service.chain._state_lock.entries
    expect_value_error(
        lambda: service.wallet_status({"scheme":"N"}),
        "object wallet-status scheme rejected",
    ); checks+=1
    assert service.chain._state_lock.entries==before,"wallet-status rejection must precede state lock"
    print("[GREEN] wallet-status scheme rejection precedes chain state lock"); checks+=1

    before=service.chain._state_lock.entries
    expect_value_error(
        lambda: service.list_unspent(True),
        "boolean list-unspent scheme rejected",
    ); checks+=1
    assert service.chain._state_lock.entries==before,"list-unspent rejection must precede state lock"
    print("[GREEN] list-unspent scheme rejection precedes chain state lock"); checks+=1

    expect_value_error(
        lambda: service.mine(1,7),
        "integer mining scheme rejected before wallet/mining work",
    ); checks+=1
    expect_value_error(
        lambda: service.send(1.0,"N"+"0"*40,1,0),
        "float send input scheme rejected before transaction work",
    ); checks+=1

    invalid=([],{},True,False,0,1,1.0,b"N")
    for value in invalid:
        expect_value_error(
            lambda value=value: core_module.AxvenCore._validate_scheme_bound(value),
            f"scheme validator rejects coercion alias: {type(value).__name__}",
        )
        checks+=1

    core_module.AxvenCore._validate_scheme_bound(None)
    print("[GREEN] optional None scheme remains accepted"); checks+=1
    core_module.AxvenCore._validate_scheme_bound(axven.SCHEME_ED25519)
    core_module.AxvenCore._validate_scheme_bound("x"*64)
    print("[GREEN] canonical and maximum bounded string schemes remain accepted"); checks+=1
    expect_value_error(
        lambda: core_module.AxvenCore._validate_scheme_bound("x"*65),
        "oversized string scheme preserves legacy bound error",
        "scheme too long",
    ); checks+=1

    validator_src=inspect.getsource(core_module.AxvenCore._validate_scheme_bound)
    assert (
        "type(scheme) is not str" in validator_src
        and "len(scheme) > 64" in validator_src
        and "len(str(scheme))" not in validator_src
    ),"production validator must not stringify attacker-controlled scheme values"
    print("[GREEN] production scheme validator contains no attacker-controlled string coercion"); checks+=1

    surfaces=("balance","wallet_status","list_unspent","mine","send")
    for name in surfaces:
        src=inspect.getsource(getattr(core_module.AxvenCore,name))
        assert "_validate_scheme_bound" in src,f"{name} lost scheme validator"
    print("[GREEN] every public scheme-taking service surface retains the shared validator"); checks+=1

    assert (
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    ),"scheme-domain hardening must leave canonical chain identity unchanged"
    print("[GREEN] scheme-domain hardening leaves canonical chain identity unchanged"); checks+=1

    print(f"SEC-140 scheme type domain: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
