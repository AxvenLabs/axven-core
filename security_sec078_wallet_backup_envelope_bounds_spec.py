#!/usr/bin/env python3
"""SEC-078 wallet backup envelope/file bounds contract."""
from __future__ import annotations

import base64
import os
import tempfile
from copy import deepcopy

import wallet


def expect_rejected_before_decode(backup, passphrase, label):
    original = wallet.base64.b64decode
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("base64 decode must not run for rejected backup envelope")

    wallet.base64.b64decode = forbidden
    try:
        try:
            wallet.restore_backup(backup, passphrase)
        except wallet.BackupError:
            pass
        else:
            raise AssertionError(label + " accepted")
    finally:
        wallet.base64.b64decode = original
    assert not calls, label + " reached base64 decode"
    print("[GREEN]", label, "rejected before base64 decode")


def expect_rejected_before_scrypt(backup, label):
    original = wallet.hashlib.scrypt
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("scrypt must not run for rejected decoded envelope")

    wallet.hashlib.scrypt = forbidden
    try:
        try:
            wallet.restore_backup(backup, "sec078-passphrase")
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

    assert wallet.MAX_BACKUP_FILE_BYTES == 64 * 1024
    assert wallet.MAX_BACKUP_CIPHERTEXT_BYTES == 16 * 1024
    checks += 1
    print("[GREEN] wallet backup byte budgets pinned")

    identity = wallet.WalletIdentity()
    backup = wallet.export_backup(identity, "sec078-passphrase")
    restored = wallet.restore_backup(deepcopy(backup), "sec078-passphrase")
    assert restored.address_n == identity.address_n
    assert restored.address_m == identity.address_m
    assert restored.address_h == identity.address_h
    checks += 1
    print("[GREEN] canonical backup round-trip preserved")

    predecode_cases = []
    predecode_cases.append(("non-object backup envelope", [], "sec078-passphrase"))
    predecode_cases.append(("empty passphrase", deepcopy(backup), ""))

    b = deepcopy(backup)
    b["version"] = "1"
    predecode_cases.append(("string backup version", b, "sec078-passphrase"))

    b = deepcopy(backup)
    b["version"] = True
    predecode_cases.append(("boolean backup version", b, "sec078-passphrase"))

    b = deepcopy(backup)
    b["salt"] = "A" * 23
    predecode_cases.append(("noncanonical salt text length", b, "sec078-passphrase"))

    b = deepcopy(backup)
    b["nonce"] = "A" * 15
    predecode_cases.append(("noncanonical nonce text length", b, "sec078-passphrase"))

    b = deepcopy(backup)
    b["ciphertext"] = "A" * (wallet._MAX_CIPHERTEXT_B64_CHARS + 1)
    predecode_cases.append(("oversized ciphertext text", b, "sec078-passphrase"))

    b = deepcopy(backup)
    b["checksum"] = "G" * 64
    predecode_cases.append(("non-hex checksum", b, "sec078-passphrase"))

    for label, candidate, passphrase in predecode_cases:
        expect_rejected_before_decode(candidate, passphrase, label)
        checks += 1

    b = deepcopy(backup)
    b["salt"] = base64.b64encode(b"S" * 17).decode("ascii")
    expect_rejected_before_scrypt(b, "decoded salt length")
    checks += 1

    b = deepcopy(backup)
    b["nonce"] = base64.b64encode(b"N" * 11).decode("ascii")
    expect_rejected_before_scrypt(b, "decoded nonce length")
    checks += 1

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "oversized.wallet")
        with open(path, "wb") as f:
            f.write(b"{" + b" " * wallet.MAX_BACKUP_FILE_BYTES)
        try:
            wallet.load_backup_file(path, "sec078-passphrase")
        except wallet.BackupError as e:
            assert "too large" in str(e)
        else:
            raise AssertionError("oversized backup file accepted")
    checks += 1
    print("[GREEN] oversized backup file rejected by bounded read")

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "invalid-utf8.wallet")
        with open(path, "wb") as f:
            f.write(b"\xff\xfe\xfd")
        try:
            wallet.load_backup_file(path, "sec078-passphrase")
        except wallet.BackupError as e:
            assert "corrupt backup file" in str(e)
        else:
            raise AssertionError("invalid UTF-8 backup file accepted")
    checks += 1
    print("[GREEN] invalid UTF-8 backup file fails closed")

    assert checks == 14
    print(f"SEC-078 wallet backup envelope bounds: {checks}/14 GREEN")


if __name__ == "__main__":
    main()
