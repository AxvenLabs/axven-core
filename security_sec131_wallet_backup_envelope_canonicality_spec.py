#!/usr/bin/env python3
"""SEC-131 canonicalize the persisted wallet backup JSON envelope."""
from __future__ import annotations

import inspect
import json
import os
import tempfile

import axven
import wallet


def _write_and_load(raw, passphrase):
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "wallet.backup")
        with open(path, "wb") as f:
            f.write(raw)
        return wallet.load_backup_file(path, passphrase)


def _raw_with_duplicate_top_level(backup, key):
    canonical = json.dumps(backup, sort_keys=True, separators=(",", ":"))
    return (
        canonical[:-1]
        + ","
        + json.dumps(key)
        + ":"
        + json.dumps(backup[key], separators=(",", ":"))
        + "}"
    ).encode("utf-8")


def _raw_with_duplicate_kdf_n(backup):
    kp = backup["kdf_params"]
    duplicate_kdf = (
        '{"n":' + str(kp["n"])
        + ',"n":' + str(kp["n"])
        + ',"r":' + str(kp["r"])
        + ',"p":' + str(kp["p"])
        + ',"dklen":' + str(kp["dklen"]) + '}'
    )
    pieces = []
    for key in sorted(backup):
        if key == "kdf_params":
            value = duplicate_kdf
        else:
            value = json.dumps(backup[key], separators=(",", ":"))
        pieces.append(json.dumps(key) + ":" + value)
    return ("{" + ",".join(pieces) + "}").encode("utf-8")


def main():
    checks = []

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    expected = {
        "version", "kdf", "kdf_params", "cipher",
        "salt", "nonce", "ciphertext", "checksum",
    }
    green(
        "wallet backup outer envelope field set is pinned exactly",
        wallet._BACKUP_ENVELOPE_FIELDS == expected,
    )

    passphrase = "sec131-canonical-passphrase"
    identity = wallet.WalletIdentity()
    backup = wallet.export_backup(identity, passphrase)
    green(
        "exported wallet backup uses the exact canonical outer schema",
        set(backup) == expected,
    )

    restored = wallet.restore_backup(backup, passphrase)
    green(
        "canonical in-memory encrypted backup round-trip is preserved",
        restored.address_n == identity.address_n
        and restored.address_m == identity.address_m
        and restored.address_h == identity.address_h,
    )

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "canonical.wallet")
        wallet.save_backup_file(identity, path, passphrase)
        loaded = wallet.load_backup_file(path, passphrase)
    green(
        "canonical persisted wallet backup round-trip is preserved",
        loaded.address_n == identity.address_n
        and loaded.address_m == identity.address_m
        and loaded.address_h == identity.address_h,
    )

    decode_calls = []
    original_b64decode = wallet.base64.b64decode

    def trap_decode(*args, **kwargs):
        decode_calls.append(1)
        raise AssertionError("base64 decode must not run before envelope schema validation")

    unknown = dict(backup)
    unknown["future"] = "ignored-by-legacy-parser"
    wallet.base64.b64decode = trap_decode
    try:
        try:
            wallet.restore_backup(unknown, passphrase)
            unknown_rejected = False
        except wallet.BackupError as exc:
            unknown_rejected = "invalid backup envelope fields" in str(exc)
    finally:
        wallet.base64.b64decode = original_b64decode
    green(
        "unknown outer backup field is rejected before base64 or KDF work",
        unknown_rejected and not decode_calls,
    )

    missing = dict(backup)
    missing.pop("checksum")
    decode_calls = []
    wallet.base64.b64decode = trap_decode
    try:
        try:
            wallet.restore_backup(missing, passphrase)
            missing_rejected = False
        except wallet.BackupError as exc:
            missing_rejected = "invalid backup envelope fields" in str(exc)
    finally:
        wallet.base64.b64decode = original_b64decode
    green(
        "missing outer backup field is rejected before base64 or KDF work",
        missing_rejected and not decode_calls,
    )

    def duplicate_rejected_before_restore(raw):
        restore_calls = []
        original_restore = wallet.restore_backup

        def trap_restore(*args, **kwargs):
            restore_calls.append(1)
            raise AssertionError("restore_backup must not receive ambiguous file JSON")

        wallet.restore_backup = trap_restore
        try:
            try:
                _write_and_load(raw, passphrase)
                rejected = False
            except wallet.BackupError as exc:
                rejected = "duplicate backup JSON field" in str(exc)
        finally:
            wallet.restore_backup = original_restore
        return rejected and not restore_calls

    green(
        "duplicate top-level version is rejected before restore dispatch",
        duplicate_rejected_before_restore(
            _raw_with_duplicate_top_level(backup, "version")
        ),
    )
    green(
        "duplicate top-level ciphertext is rejected before restore dispatch",
        duplicate_rejected_before_restore(
            _raw_with_duplicate_top_level(backup, "ciphertext")
        ),
    )
    green(
        "duplicate nested scrypt parameter is rejected before restore dispatch",
        duplicate_rejected_before_restore(_raw_with_duplicate_kdf_n(backup)),
    )

    unknown_file = dict(backup)
    unknown_file["ignored"] = None
    try:
        _write_and_load(
            json.dumps(unknown_file, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            passphrase,
        )
        unknown_file_rejected = False
    except wallet.BackupError as exc:
        unknown_file_rejected = "invalid backup envelope fields" in str(exc)
    green("persisted backup rejects unknown outer fields", unknown_file_rejected)

    malformed_calls = []
    original_loads = wallet.json.loads

    def counting_loads(*args, **kwargs):
        malformed_calls.append(1)
        return original_loads(*args, **kwargs)

    wallet.json.loads = counting_loads
    try:
        try:
            _write_and_load(b'{"version":]', passphrase)
            malformed_rejected = False
        except wallet.BackupError:
            malformed_rejected = True
    finally:
        wallet.json.loads = original_loads
    green(
        "ordinary shallow malformed backup JSON still reaches parser and fails closed",
        malformed_rejected and len(malformed_calls) == 1,
    )

    validate_src = inspect.getsource(wallet._validated_backup_envelope)
    green(
        "exact outer schema gate precedes field semantics and expensive decoding",
        "set(backup) != _BACKUP_ENVELOPE_FIELDS" in validate_src
        and validate_src.index("set(backup) != _BACKUP_ENVELOPE_FIELDS")
        < validate_src.index('backup.get("version")'),
    )

    load_src = inspect.getsource(wallet.load_backup_file)
    green(
        "bounded-read and SEC-128 preflight remain before duplicate-aware parser",
        load_src.index("len(raw) > MAX_BACKUP_FILE_BYTES")
        < load_src.index("_preflight_backup_json_nesting(raw)")
        < load_src.index("json.loads(raw.decode")
        and "object_pairs_hook=_reject_duplicate_backup_file_keys" in load_src,
    )

    hook_src = inspect.getsource(wallet._reject_duplicate_backup_file_keys)
    green(
        "outer duplicate-key parser hook is fail-closed and recursive",
        "if key in out" in hook_src
        and "duplicate backup JSON field" in hook_src,
    )

    green(
        "wallet envelope canonicality leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-131 wallet backup envelope canonicality: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
