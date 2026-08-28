#!/usr/bin/env python3
"""SEC-127 canonicalize authenticated wallet backup key material after decrypt."""

from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import axven
import wallet

PASSPHRASE="sec127-passphrase"
AAD=b"axven-wallet-backup-v1"


def identity():
    ed=axven.Wallet()
    return wallet.WalletIdentity(
        ed_keypair=(ed.public_key,ed.private_key),
        ml_keypair=(b"Q" * wallet.ML_DSA_PUBLIC_KEY_BYTES,
                    b"S" * wallet.ML_DSA_SECRET_KEY_BYTES),
    )


def canonical_material(ident):
    return {
        "ed_private":base64.b64encode(wallet._raw_ed_private(ident)).decode("ascii"),
        "ml_public":base64.b64encode(ident.ml_public_key).decode("ascii"),
        "ml_secret":base64.b64encode(ident.ml_secret_key).decode("ascii"),
    }


def authenticated_backup_with_plain(base_backup, passphrase, plain):
    forged=copy.deepcopy(base_backup)
    salt=base64.b64decode(forged["salt"],validate=True)
    nonce=base64.b64decode(forged["nonce"],validate=True)
    kp=forged["kdf_params"]
    key=hashlib.scrypt(
        passphrase.encode(),salt=salt,n=kp["n"],r=kp["r"],p=kp["p"],dklen=kp["dklen"],
    )
    cipher=AESGCM(key).encrypt(nonce,plain,AAD)
    forged["ciphertext"]=base64.b64encode(cipher).decode("ascii")
    forged["checksum"]=hashlib.sha256(cipher).hexdigest()
    return forged


def authenticated_backup_with_material(base_backup, passphrase, material):
    plain=json.dumps(material,sort_keys=True,separators=(",",":")).encode("utf-8")
    return authenticated_backup_with_plain(base_backup,passphrase,plain)


def rejected(backup):
    try:
        wallet.restore_backup(backup,PASSPHRASE)
    except wallet.BackupError:
        return True
    return False


def main():
    checks=[]
    def green(name,condition):
        assert condition,name
        checks.append(name)
        print("[GREEN]",name)

    green(
        "wallet key-material byte sizes pinned to runtime crypto formats",
        wallet.ED25519_PRIVATE_KEY_BYTES == 32
        and wallet.ML_DSA_PUBLIC_KEY_BYTES == 1312
        and wallet.ML_DSA_SECRET_KEY_BYTES == 2560,
    )

    ident=identity()
    backup=wallet.export_backup(ident,PASSPHRASE)
    restored=wallet.restore_backup(backup,PASSPHRASE)
    green(
        "canonical encrypted backup round-trip preserves wallet identity",
        wallet._raw_ed_private(restored) == wallet._raw_ed_private(ident)
        and restored.ml_public_key == ident.ml_public_key
        and restored.ml_secret_key == ident.ml_secret_key
        and restored.address_n == ident.address_n
        and restored.address_m == ident.address_m
        and restored.address_h == ident.address_h,
    )

    material=canonical_material(ident)
    unknown=dict(material); unknown["extra"]="x"
    green(
        "authenticated inner material rejects unknown fields",
        rejected(authenticated_backup_with_material(backup,PASSPHRASE,unknown)),
    )
    missing=dict(material); missing.pop("ml_secret")
    green(
        "authenticated inner material rejects missing fields",
        rejected(authenticated_backup_with_material(backup,PASSPHRASE,missing)),
    )

    type_cases=[]
    for field in ("ed_private","ml_public","ml_secret"):
        bad=dict(material); bad[field]=0
        type_cases.append(rejected(authenticated_backup_with_material(backup,PASSPHRASE,bad)))
    green("authenticated inner key fields require exact strings",all(type_cases))

    bad_b64=dict(material); bad_b64["ml_public"]="!" * 16
    green(
        "authenticated inner material rejects malformed base64",
        rejected(authenticated_backup_with_material(backup,PASSPHRASE,bad_b64)),
    )

    ed_lengths=[]
    for size in (31,33):
        bad=dict(material); bad["ed_private"]=base64.b64encode(b"E"*size).decode("ascii")
        ed_lengths.append(rejected(authenticated_backup_with_material(backup,PASSPHRASE,bad)))
    green("Ed25519 private key length is exact before constructor",all(ed_lengths))

    ml_pub_lengths=[]
    for size in (wallet.ML_DSA_PUBLIC_KEY_BYTES-1,wallet.ML_DSA_PUBLIC_KEY_BYTES+1):
        bad=dict(material); bad["ml_public"]=base64.b64encode(b"P"*size).decode("ascii")
        ml_pub_lengths.append(rejected(authenticated_backup_with_material(backup,PASSPHRASE,bad)))
    green("ML-DSA public key length is exact before wallet construction",all(ml_pub_lengths))

    ml_sec_lengths=[]
    for size in (wallet.ML_DSA_SECRET_KEY_BYTES-1,wallet.ML_DSA_SECRET_KEY_BYTES+1):
        bad=dict(material); bad["ml_secret"]=base64.b64encode(b"K"*size).decode("ascii")
        ml_sec_lengths.append(rejected(authenticated_backup_with_material(backup,PASSPHRASE,bad)))
    green("ML-DSA secret key length is exact before wallet construction",all(ml_sec_lengths))

    # Build raw JSON rather than a dict so the duplicate survives serialization.
    dup=(
        '{"ed_private":'+json.dumps(material["ed_private"])
        +',"ed_private":'+json.dumps(material["ed_private"])
        +',"ml_public":'+json.dumps(material["ml_public"])
        +',"ml_secret":'+json.dumps(material["ml_secret"])+"}"
    ).encode("utf-8")
    green(
        "authenticated inner material rejects duplicate JSON keys",
        rejected(authenticated_backup_with_plain(backup,PASSPHRASE,dup)),
    )

    malformed=b'{"ed_private":'
    green(
        "authenticated malformed inner JSON fails closed after successful decrypt",
        rejected(authenticated_backup_with_plain(backup,PASSPHRASE,malformed)),
    )

    exact=authenticated_backup_with_material(backup,PASSPHRASE,material)
    exact_restored=wallet.restore_backup(exact,PASSPHRASE)
    green(
        "exact authenticated material remains accepted",
        exact_restored.ml_public_key == ident.ml_public_key
        and exact_restored.ml_secret_key == ident.ml_secret_key,
    )

    helper_src=inspect.getsource(wallet._validated_backup_material)
    restore_src=inspect.getsource(wallet.restore_backup)
    green(
        "production validator enforces exact fields duplicate rejection and key lengths",
        "object_pairs_hook=_reject_duplicate_backup_material_keys" in helper_src
        and 'set(material) != expected' in helper_src
        and "ED25519_PRIVATE_KEY_BYTES" in helper_src
        and "ML_DSA_PUBLIC_KEY_BYTES" in helper_src
        and "ML_DSA_SECRET_KEY_BYTES" in helper_src,
    )
    green(
        "restore validates decrypted material before key constructors",
        "_validated_backup_material(plain)" in restore_src
        and restore_src.index("_validated_backup_material(plain)")
            < restore_src.index("Ed25519PrivateKey.from_private_bytes"),
    )

    green(
        "wallet material hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-127 wallet inner material canonicality: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
