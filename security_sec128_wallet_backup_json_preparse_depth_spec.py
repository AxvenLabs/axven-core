#!/usr/bin/env python3
"""SEC-128 bound wallet backup JSON nesting before json.loads."""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import axven
import wallet


def _nested_array_raw(levels):
    return b"[" * levels + b"0" + b"]" * levels


def _authenticated_backup_with_plain(plain, passphrase):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.scrypt(
        passphrase.encode(),
        salt=salt,
        n=wallet._SCRYPT_N,
        r=wallet._SCRYPT_R,
        p=wallet._SCRYPT_P,
        dklen=wallet._SCRYPT_DKLEN,
    )
    cipher = AESGCM(key).encrypt(nonce, plain, b"axven-wallet-backup-v1")
    return {
        "version": wallet.BACKUP_VERSION,
        "kdf": "scrypt",
        "kdf_params": dict(wallet._SCRYPT_PARAMS),
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(cipher).decode("ascii"),
        "checksum": hashlib.sha256(cipher).hexdigest(),
    }


def main():
    checks = []

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "wallet backup raw JSON nesting limit pinned above canonical envelope depth",
        wallet.MAX_BACKUP_JSON_NESTING_DEPTH == 32,
    )

    wallet._preflight_backup_json_nesting(_nested_array_raw(32))
    green("exact backup JSON nesting boundary accepted", True)

    try:
        wallet._preflight_backup_json_nesting(_nested_array_raw(33))
        over_depth = False
    except wallet.BackupError as exc:
        over_depth = "nesting depth exceeded" in str(exc)
    green("over-depth backup JSON rejected by raw preflight", over_depth)

    string_payload = json.dumps(
        {"text": ("[{" * 80) + '\\\"quoted\\\\text' + ("}]" * 80)},
        separators=(",", ":"),
    ).encode("utf-8")
    wallet._preflight_backup_json_nesting(string_payload)
    green("container-looking bytes inside backup JSON strings are ignored", True)

    try:
        wallet._preflight_backup_json_nesting(b"}" * 64 + b"[" * 33)
        unmatched_blocked = False
    except wallet.BackupError:
        unmatched_blocked = True
    green("unmatched closers cannot reset backup JSON nesting depth", unmatched_blocked)

    try:
        wallet._preflight_backup_json_nesting(b"{" + b"]" * 64 + b"[" * 32)
        mismatch_blocked = False
    except wallet.BackupError:
        mismatch_blocked = True
    green("mismatched closers cannot pop unlike backup JSON openers", mismatch_blocked)

    with tempfile.TemporaryDirectory() as td:
        deep_path = os.path.join(td, "deep.wallet")
        with open(deep_path, "wb") as f:
            f.write(_nested_array_raw(33))
        parser_calls = []
        original_loads = wallet.json.loads

        def trap_loads(*args, **kwargs):
            parser_calls.append(1)
            raise AssertionError("json.loads must not run for over-depth backup file")

        wallet.json.loads = trap_loads
        try:
            try:
                wallet.load_backup_file(deep_path, "sec128-passphrase")
                outer_rejected = False
            except wallet.BackupError as exc:
                outer_rejected = "nesting depth exceeded" in str(exc)
        finally:
            wallet.json.loads = original_loads
    green(
        "backup file path rejects over-depth JSON before json.loads",
        outer_rejected and not parser_calls,
    )

    passphrase = "sec128-inner-passphrase"
    inner_deep = _authenticated_backup_with_plain(_nested_array_raw(33), passphrase)
    parser_calls = []
    original_loads = wallet.json.loads

    def trap_inner_loads(*args, **kwargs):
        parser_calls.append(1)
        raise AssertionError("json.loads must not run for over-depth decrypted material")

    wallet.json.loads = trap_inner_loads
    try:
        try:
            wallet.restore_backup(inner_deep, passphrase)
            inner_rejected = False
        except wallet.BackupError as exc:
            inner_rejected = "nesting depth exceeded" in str(exc)
    finally:
        wallet.json.loads = original_loads
    green(
        "authenticated decrypted material rejects over-depth JSON before json.loads",
        inner_rejected and not parser_calls,
    )

    identity = wallet.WalletIdentity()
    canonical = wallet.export_backup(identity, "sec128-roundtrip")
    restored = wallet.restore_backup(canonical, "sec128-roundtrip")
    green(
        "canonical encrypted backup round-trip preserved",
        restored.address_n == identity.address_n
        and restored.address_m == identity.address_m
        and restored.address_h == identity.address_h,
    )

    with tempfile.TemporaryDirectory() as td:
        malformed_path = os.path.join(td, "malformed.wallet")
        with open(malformed_path, "wb") as f:
            f.write(b'{"version":]')
        parser_calls = []
        original_loads = wallet.json.loads

        def counting_loads(*args, **kwargs):
            parser_calls.append(1)
            return original_loads(*args, **kwargs)

        wallet.json.loads = counting_loads
        try:
            try:
                wallet.load_backup_file(malformed_path, "sec128-passphrase")
                malformed_closed = False
            except wallet.BackupError:
                malformed_closed = True
        finally:
            wallet.json.loads = original_loads
    green(
        "ordinary shallow malformed backup JSON still reaches canonical parser and fails closed",
        malformed_closed and len(parser_calls) == 1,
    )

    load_src = inspect.getsource(wallet.load_backup_file)
    green(
        "backup file production order is bounded read then preflight then json.loads",
        load_src.index("len(raw) > MAX_BACKUP_FILE_BYTES")
        < load_src.index("_preflight_backup_json_nesting(raw)")
        < load_src.index("json.loads(raw.decode"),
    )

    restore_src = inspect.getsource(wallet.restore_backup)
    green(
        "decrypted material production order is authenticated decrypt then preflight then json.loads",
        restore_src.index("AESGCM(key).decrypt")
        < restore_src.index("_preflight_backup_json_nesting(plain)")
        < restore_src.index("json.loads("),
    )

    green(
        "wallet JSON parser hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-128 wallet backup JSON pre-parse depth: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
