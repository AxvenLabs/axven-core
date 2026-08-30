#!/usr/bin/env python3
"""SEC-191: strengthen new wallet backup KDF while retaining legacy restore."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import wallet


LEGACY = {"n": 1 << 14, "r": 8, "p": 1, "dklen": 32}


def _legacy_backup(identity, passphrase):
    material = {
        "ed_private": base64.b64encode(wallet._raw_ed_private(identity)).decode("ascii"),
        "ml_public": base64.b64encode(identity.ml_public_key).decode("ascii"),
        "ml_secret": base64.b64encode(identity.ml_secret_key).decode("ascii"),
    }
    plain = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.scrypt(
        passphrase.encode(), salt=salt,
        n=LEGACY["n"], r=LEGACY["r"], p=LEGACY["p"], dklen=LEGACY["dklen"],
    )
    cipher = AESGCM(key).encrypt(nonce, plain, b"axven-wallet-backup-v1")
    return {
        "version": wallet.BACKUP_VERSION,
        "kdf": "scrypt",
        "kdf_params": dict(LEGACY),
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(cipher).decode("ascii"),
        "checksum": hashlib.sha256(cipher).hexdigest(),
    }


def main():
    checks=[]
    def green(name, condition=True):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    green("new backup KDF stronger than legacy", wallet._SCRYPT_PARAMS != LEGACY and wallet._SCRYPT_PARAMS["n"] >= (1 << 17))
    green("legacy KDF accepted only for restore compatibility", wallet._validated_scrypt_params(dict(LEGACY)) == LEGACY)

    try:
        wallet._validated_scrypt_params({"n":1 << 15,"r":8,"p":1,"dklen":32})
    except wallet.BackupError:
        green("unapproved attacker-selected KDF parameters rejected")
    else:
        raise AssertionError("unapproved KDF parameters accepted")

    identity=wallet.WalletIdentity()
    backup=wallet.export_backup(identity,"sec191-passphrase")
    green("new exports advertise strengthened KDF", backup["kdf_params"] == wallet._SCRYPT_PARAMS)
    restored=wallet.restore_backup(backup,"sec191-passphrase")
    green("strengthened backup roundtrip succeeds", restored.ml_public_key == identity.ml_public_key)

    legacy_backup=_legacy_backup(identity,"sec191-legacy")
    legacy_restored=wallet.restore_backup(legacy_backup,"sec191-legacy")
    green("legacy encrypted backup remains recoverable", legacy_restored.ml_public_key == identity.ml_public_key)

    print(f"SEC-191 wallet KDF hardening: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
