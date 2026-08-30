#!/usr/bin/env python3
"""SEC-191: strengthen wallet backup scrypt while preserving exact legacy restore."""
from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import axven
import wallet


def make_legacy_backup(identity, passphrase):
    material = {
        "ed_private": base64.b64encode(wallet._raw_ed_private(identity)).decode("ascii"),
        "ml_public": base64.b64encode(identity.ml_public_key).decode("ascii"),
        "ml_secret": base64.b64encode(identity.ml_secret_key).decode("ascii"),
    }
    plain = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    salt = b"L" * 16
    nonce = b"N" * 12
    key = hashlib.scrypt(
        passphrase.encode(),
        salt=salt,
        n=1 << 14,
        r=8,
        p=1,
        dklen=32,
        maxmem=wallet._SCRYPT_MAXMEM,
    )
    cipher = AESGCM(key).encrypt(nonce, plain, b"axven-wallet-backup-v1")
    return {
        "version": wallet.BACKUP_VERSION,
        "kdf": "scrypt",
        "kdf_params": {"n": 1 << 14, "r": 8, "p": 1, "dklen": 32},
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(cipher).decode("ascii"),
        "checksum": hashlib.sha256(cipher).hexdigest(),
    }


def main():
    checks = []

    def green(name, condition=True):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    current = {"n": 1 << 17, "r": 8, "p": 1, "dklen": 32}
    legacy = {"n": 1 << 14, "r": 8, "p": 1, "dklen": 32}
    green("new backups pin the strengthened scrypt profile", wallet._SCRYPT_PARAMS == current)
    green("legacy restore profile remains exact", wallet._SCRYPT_LEGACY_PARAMS == legacy)
    green("scrypt memory ceiling is fixed at 256 MiB", wallet._SCRYPT_MAXMEM == 256 * 1024 * 1024)

    identity = wallet.WalletIdentity()
    new_backup = wallet.export_backup(identity, "sec191-new-pass")
    green("new export advertises only the strengthened profile", new_backup["kdf_params"] == current)
    restored = wallet.restore_backup(deepcopy(new_backup), "sec191-new-pass")
    green(
        "strengthened backup round-trip preserves identity",
        restored.address_n == identity.address_n
        and restored.address_m == identity.address_m
        and restored.address_h == identity.address_h,
    )

    legacy_backup = make_legacy_backup(identity, "sec191-legacy-pass")
    legacy_restored = wallet.restore_backup(legacy_backup, "sec191-legacy-pass")
    green(
        "exact legacy backup remains restorable",
        legacy_restored.address_n == identity.address_n
        and legacy_restored.address_m == identity.address_m
        and legacy_restored.address_h == identity.address_h,
    )

    candidate = deepcopy(new_backup)
    candidate["kdf_params"]["n"] = 1 << 15
    original = wallet.hashlib.scrypt
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("unapproved KDF parameters reached scrypt")

    wallet.hashlib.scrypt = forbidden
    try:
        try:
            wallet.restore_backup(candidate, "sec191-new-pass")
        except wallet.BackupError:
            pass
        else:
            raise AssertionError("intermediate scrypt profile accepted")
    finally:
        wallet.hashlib.scrypt = original
    green("unapproved KDF profile rejects before scrypt", not calls)

    real_scrypt = wallet.hashlib.scrypt
    tracked = []

    def tracking_scrypt(password, **kwargs):
        tracked.append(dict(kwargs))
        return real_scrypt(password, **kwargs)

    wallet.hashlib.scrypt = tracking_scrypt
    try:
        tracked_backup = wallet.export_backup(identity, "sec191-maxmem-pass")
        wallet.restore_backup(tracked_backup, "sec191-maxmem-pass")
    finally:
        wallet.hashlib.scrypt = real_scrypt
    green(
        "export and restore enforce the fixed scrypt memory ceiling",
        len(tracked) == 2
        and all(call.get("maxmem") == wallet._SCRYPT_MAXMEM for call in tracked)
        and all(call.get("n") == 1 << 17 for call in tracked),
    )

    green(
        "chain identity and PQ activation semantics unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000,
    )

    print(f"SEC-191 wallet KDF strength: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
