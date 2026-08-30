#!/usr/bin/env python3
"""SEC-192: bound wallet-backup passphrase resources before scrypt work."""
from __future__ import annotations

import inspect
from copy import deepcopy

import axven
import wallet


def rejected(fn):
    try:
        fn()
    except wallet.BackupError:
        return True
    return False


def main():
    checks = []

    def green(name, condition=True):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    green(
        "wallet backup passphrase byte budget pinned",
        wallet.MAX_BACKUP_PASSPHRASE_BYTES == 1024,
    )

    boundary = "A" * 1024
    boundary_bytes = wallet._validated_passphrase_bytes(boundary)
    green(
        "exact 1024-byte passphrase remains accepted without truncation",
        boundary_bytes == b"A" * 1024 and len(boundary_bytes) == 1024,
    )

    unicode_boundary = "é" * 512
    green(
        "passphrase budget is measured in UTF-8 bytes",
        len(wallet._validated_passphrase_bytes(unicode_boundary)) == 1024
        and rejected(lambda: wallet._validated_passphrase_bytes("é" * 513)),
    )

    class PassphraseSubclass(str):
        pass

    green(
        "passphrase type is exact and empty input fails closed",
        rejected(lambda: wallet._validated_passphrase_bytes(""))
        and rejected(lambda: wallet._validated_passphrase_bytes(b"bytes"))
        and rejected(lambda: wallet._validated_passphrase_bytes(PassphraseSubclass("x")))
        and rejected(lambda: wallet._validated_passphrase_bytes(None)),
    )

    invalid_unicode = chr(0xD800)
    green(
        "invalid Unicode passphrase encoding fails closed",
        rejected(lambda: wallet._validated_passphrase_bytes(invalid_unicode)),
    )

    identity = wallet.WalletIdentity()
    canonical = wallet.export_backup(identity, "sec192-canonical-pass")

    original_scrypt = wallet.hashlib.scrypt
    scrypt_calls = []

    def forbidden_scrypt(*args, **kwargs):
        scrypt_calls.append((args, kwargs))
        raise AssertionError("rejected passphrase reached scrypt")

    wallet.hashlib.scrypt = forbidden_scrypt
    try:
        oversized_export = rejected(
            lambda: wallet.export_backup(identity, "X" * 1025)
        )
        invalid_export = rejected(
            lambda: wallet.export_backup(identity, invalid_unicode)
        )
    finally:
        wallet.hashlib.scrypt = original_scrypt
    green(
        "export rejects oversized and invalid passphrases before scrypt",
        oversized_export and invalid_export and not scrypt_calls,
    )

    original_scrypt = wallet.hashlib.scrypt
    original_decode = wallet.base64.b64decode
    expensive_calls = []

    def trap_scrypt(*args, **kwargs):
        expensive_calls.append("scrypt")
        raise AssertionError("oversized restore passphrase reached scrypt")

    def trap_decode(*args, **kwargs):
        expensive_calls.append("decode")
        raise AssertionError("oversized restore passphrase reached base64 decode")

    wallet.hashlib.scrypt = trap_scrypt
    wallet.base64.b64decode = trap_decode
    try:
        oversized_restore = rejected(
            lambda: wallet.restore_backup(deepcopy(canonical), "X" * 1025)
        )
    finally:
        wallet.hashlib.scrypt = original_scrypt
        wallet.base64.b64decode = original_decode
    green(
        "restore rejects oversized passphrase before decode or scrypt",
        oversized_restore and not expensive_calls,
    )

    boundary_backup = wallet.export_backup(identity, boundary)
    boundary_restored = wallet.restore_backup(boundary_backup, boundary)
    green(
        "maximum-size passphrase preserves encrypted backup round-trip",
        boundary_restored.address_n == identity.address_n
        and boundary_restored.address_m == identity.address_m
        and boundary_restored.address_h == identity.address_h,
    )

    helper_src = inspect.getsource(wallet._validated_passphrase_bytes)
    envelope_src = inspect.getsource(wallet._validated_backup_envelope)
    export_src = inspect.getsource(wallet.export_backup)
    restore_src = inspect.getsource(wallet.restore_backup)
    green(
        "production validator encodes once, bounds bytes, and never truncates",
        'type(passphrase) is not str' in helper_src
        and 'passphrase.encode("utf-8")' in helper_src
        and 'len(encoded) > MAX_BACKUP_PASSPHRASE_BYTES' in helper_src
        and 'return encoded' in helper_src
        and '[:' not in helper_src,
    )
    green(
        "export and restore enforce passphrase validation before KDF work",
        export_src.index("_validated_passphrase_bytes(passphrase)")
        < export_src.index("hashlib.scrypt(")
        and restore_src.index("_validated_passphrase_bytes(passphrase)")
        < restore_src.index("_validated_backup_envelope(")
        < restore_src.index("base64.b64decode")
        < restore_src.index("hashlib.scrypt(")
        and "hashlib.scrypt(passphrase_bytes" in export_src
        and "hashlib.scrypt(passphrase_bytes" in restore_src
        and "_validated_passphrase_bytes(passphrase)" in envelope_src,
    )

    green(
        "SEC-192 leaves chain identity and PQ activation semantics unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks) == 10
    print("SEC-192 wallet passphrase resource bounds: 10/10 GREEN")


if __name__ == "__main__":
    main()
