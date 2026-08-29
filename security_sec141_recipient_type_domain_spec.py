#!/usr/bin/env python3
"""SEC-141 enforces an exact textual recipient domain before wallet work."""

import inspect

import axven
import core as core_module


def expect_value_error(call, label, message):
    try:
        call()
    except ValueError as exc:
        ok = str(exc) == message
    else:
        ok = False
    assert ok, label
    print("[GREEN]", label)


def main():
    checks = 0
    service = object.__new__(core_module.AxvenCore)
    service.identity = None

    invalid = ([], {}, True, False, 0, 1, 1.0, b"N", None)
    for value in invalid:
        expect_value_error(
            lambda value=value: service.send(axven.SCHEME_ED25519, value, 1, 0),
            f"recipient coercion alias rejected before wallet work: {type(value).__name__}",
            "recipient address must be string",
        )
        checks += 1

    canonical = "N" + ("a" * 40)
    try:
        service.send(axven.SCHEME_ED25519, canonical, 1, 0)
    except RuntimeError as exc:
        assert str(exc) == "wallet not loaded"
    else:
        raise AssertionError("canonical string recipient must reach wallet path")
    print("[GREEN] canonical string recipient reaches normal wallet path"); checks += 1

    maximum = "N" + ("a" * 255)
    try:
        service.send(axven.SCHEME_ED25519, maximum, 1, 0)
    except RuntimeError as exc:
        assert str(exc) == "wallet not loaded"
    else:
        raise AssertionError("maximum bounded string recipient must reach wallet path")
    print("[GREEN] legacy 256-character string boundary remains downstream-compatible"); checks += 1

    expect_value_error(
        lambda: service.send(axven.SCHEME_ED25519, "N" + ("a" * 256), 1, 0),
        "oversized string recipient preserves legacy bound error",
        "recipient address too long",
    ); checks += 1

    validator_src = inspect.getsource(core_module.AxvenCore._validate_recipient_bound)
    assert (
        "type(recipient) is not str" in validator_src
        and "len(recipient) > 256" in validator_src
        and "str(recipient)" not in validator_src
    ), "recipient validator must not stringify attacker-controlled values"
    print("[GREEN] recipient validator contains no attacker-controlled string coercion"); checks += 1

    send_src = inspect.getsource(core_module.AxvenCore.send)
    assert "_validate_recipient_bound(recipient)" in send_src
    assert send_src.index("_validate_recipient_bound(recipient)") < send_src.index("require_wallet()")
    assert send_src.index("_validate_recipient_bound(recipient)") < send_src.index("build_transaction")
    print("[GREEN] send validates recipient before wallet and transaction work"); checks += 1

    assert (
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    ), "recipient-domain hardening must leave canonical chain identity unchanged"
    print("[GREEN] recipient-domain hardening leaves canonical chain identity unchanged"); checks += 1

    print(f"SEC-141 recipient type domain: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
