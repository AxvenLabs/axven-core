#!/usr/bin/env python3
"""SEC-077 wallet backup KDF resource bounds contract."""
from __future__ import annotations

from copy import deepcopy

import wallet


def expect_rejected_before_scrypt(backup, label):
    original = wallet.hashlib.scrypt
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("scrypt must not run for rejected backup parameters")

    wallet.hashlib.scrypt = forbidden
    try:
        try:
            wallet.restore_backup(backup, "sec077-passphrase")
        except wallet.BackupError:
            pass
        else:
            raise AssertionError(label + " accepted")
    finally:
        wallet.hashlib.scrypt = original
    assert not calls, label + " reached scrypt"
    print("[GREEN]", label, "rejected before scrypt")


def main():
    checks = 0
    expected = {"n": 1 << 14, "r": 8, "p": 1, "dklen": 32}
    assert wallet._SCRYPT_PARAMS == expected
    checks += 1
    print("[GREEN] canonical scrypt parameters pinned")

    identity = wallet.WalletIdentity()
    backup = wallet.export_backup(identity, "sec077-passphrase")
    restored = wallet.restore_backup(deepcopy(backup), "sec077-passphrase")
    assert restored.address_n == identity.address_n
    assert restored.address_m == identity.address_m
    assert restored.address_h == identity.address_h
    checks += 1
    print("[GREEN] canonical backup round-trip preserved")

    bad_cases = []

    b = deepcopy(backup)
    b["kdf_params"] = None
    bad_cases.append(("non-object kdf_params", b))

    b = deepcopy(backup)
    del b["kdf_params"]["n"]
    bad_cases.append(("missing kdf parameter", b))

    b = deepcopy(backup)
    b["kdf_params"]["extra"] = 1
    bad_cases.append(("unknown kdf parameter", b))

    b = deepcopy(backup)
    b["kdf_params"]["n"] = str(1 << 14)
    bad_cases.append(("string scrypt n", b))

    b = deepcopy(backup)
    b["kdf_params"]["n"] = True
    bad_cases.append(("boolean scrypt n", b))

    b = deepcopy(backup)
    b["kdf_params"]["r"] = 8.0
    bad_cases.append(("float scrypt r", b))

    b = deepcopy(backup)
    b["kdf_params"]["n"] = 1 << 20
    bad_cases.append(("oversized scrypt n", b))

    b = deepcopy(backup)
    b["kdf_params"]["r"] = 9
    bad_cases.append(("noncanonical scrypt r", b))

    b = deepcopy(backup)
    b["kdf_params"]["p"] = 2
    bad_cases.append(("noncanonical scrypt p", b))

    b = deepcopy(backup)
    b["kdf_params"]["dklen"] = 64
    bad_cases.append(("noncanonical scrypt dklen", b))

    for label, candidate in bad_cases:
        expect_rejected_before_scrypt(candidate, label)
        checks += 1

    assert checks == 12
    print(f"SEC-077 wallet backup KDF resource bounds: {checks}/12 GREEN")


if __name__ == "__main__":
    main()
