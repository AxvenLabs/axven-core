#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WALLET = ROOT / "wallet.py"
SPEC = ROOT / "security_sec129_wallet_inner_material_canonicality_spec.py"
MANIFEST = ROOT / "release_manifest.json"
WORKFLOW = ROOT / ".github" / "workflows" / "sec129-apply.yml"
SELF = Path(__file__).resolve()

src = WALLET.read_text(encoding="utf-8")

anchor = "MAX_BACKUP_JSON_NESTING_DEPTH = 32\n_MAX_CIPHERTEXT_B64_CHARS"
replacement = (
    "MAX_BACKUP_JSON_NESTING_DEPTH = 32\n"
    "ED25519_PRIVATE_KEY_BYTES = 32\n"
    "ML_DSA_PUBLIC_KEY_BYTES = 1312\n"
    "ML_DSA_SECRET_KEY_BYTES = 2560\n"
    "_MAX_CIPHERTEXT_B64_CHARS"
)
assert src.count(anchor) == 1, "SEC-129 constants anchor changed"
src = src.replace(anchor, replacement, 1)

anchor = "def _raw_ed_private(identity):\n"
helpers = '''def _reject_duplicate_backup_material_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise BackupError("duplicate backup material field")
        out[key] = value
    return out


def _validated_backup_material(material):
    expected = {"ed_private", "ml_public", "ml_secret"}
    if type(material) is not dict or set(material) != expected:
        raise BackupError("invalid backup material fields")

    values = []
    for name in ("ed_private", "ml_public", "ml_secret"):
        text = material[name]
        if type(text) is not str:
            raise BackupError("invalid backup material value")
        try:
            values.append(base64.b64decode(text, validate=True))
        except Exception as exc:
            raise BackupError("invalid backup material encoding") from exc

    ed_raw, ml_pub, ml_sec = values
    if len(ed_raw) != ED25519_PRIVATE_KEY_BYTES:
        raise BackupError("invalid Ed25519 private key length")
    if len(ml_pub) != ML_DSA_PUBLIC_KEY_BYTES:
        raise BackupError("invalid ML-DSA public key length")
    if len(ml_sec) != ML_DSA_SECRET_KEY_BYTES:
        raise BackupError("invalid ML-DSA secret key length")
    return ed_raw, ml_pub, ml_sec


def _validate_mldsa_keypair(ml_pub, ml_sec):
    message = hashlib.sha256(
        b"axven-wallet-backup-mldsa-keypair-v1|" + ml_pub
    ).digest()
    try:
        scheme = axven._mldsa()
        signature = scheme.sign(ml_sec, message)
        valid = bool(scheme.verify(ml_pub, message, signature))
    except Exception as exc:
        raise BackupError("invalid ML-DSA keypair") from exc
    if not valid:
        raise BackupError("invalid ML-DSA keypair")


'''
assert src.count(anchor) == 1, "SEC-129 helper anchor changed"
src = src.replace(anchor, helpers + anchor, 1)

old = '''        plain = AESGCM(key).decrypt(nonce, cipher, b"axven-wallet-backup-v1")
        _preflight_backup_json_nesting(plain)
        material = json.loads(plain)
        ed_raw = base64.b64decode(material["ed_private"], validate=True)
        ml_pub = base64.b64decode(material["ml_public"], validate=True)
        ml_sec = base64.b64decode(material["ml_secret"], validate=True)
        ed_priv = Ed25519PrivateKey.from_private_bytes(ed_raw)
'''
new = '''        plain = AESGCM(key).decrypt(nonce, cipher, b"axven-wallet-backup-v1")
        _preflight_backup_json_nesting(plain)
        try:
            material = json.loads(
                plain,
                object_pairs_hook=_reject_duplicate_backup_material_keys,
            )
        except BackupError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise BackupError("invalid backup material JSON") from exc
        ed_raw, ml_pub, ml_sec = _validated_backup_material(material)
        _validate_mldsa_keypair(ml_pub, ml_sec)
        ed_priv = Ed25519PrivateKey.from_private_bytes(ed_raw)
'''
assert src.count(old) == 1, "SEC-129 restore anchor changed"
src = src.replace(old, new, 1)

WALLET.write_text(src, encoding="utf-8", newline="\n")

spec = r'''#!/usr/bin/env python3
"""SEC-129 canonicalize authenticated wallet backup key material."""
from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import axven
import wallet

PASSPHRASE = "sec129-passphrase"
AAD = b"axven-wallet-backup-v1"


def canonical_material(ident):
    return {
        "ed_private": base64.b64encode(wallet._raw_ed_private(ident)).decode("ascii"),
        "ml_public": base64.b64encode(ident.ml_public_key).decode("ascii"),
        "ml_secret": base64.b64encode(ident.ml_secret_key).decode("ascii"),
    }


def authenticated_backup_with_plain(base_backup, passphrase, plain):
    forged = copy.deepcopy(base_backup)
    salt = base64.b64decode(forged["salt"], validate=True)
    nonce = base64.b64decode(forged["nonce"], validate=True)
    kp = forged["kdf_params"]
    key = hashlib.scrypt(
        passphrase.encode(),
        salt=salt,
        n=kp["n"],
        r=kp["r"],
        p=kp["p"],
        dklen=kp["dklen"],
    )
    cipher = AESGCM(key).encrypt(nonce, plain, AAD)
    forged["ciphertext"] = base64.b64encode(cipher).decode("ascii")
    forged["checksum"] = hashlib.sha256(cipher).hexdigest()
    return forged


def authenticated_backup_with_material(base_backup, passphrase, material):
    plain = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return authenticated_backup_with_plain(base_backup, passphrase, plain)


def rejected(backup):
    try:
        wallet.restore_backup(backup, PASSPHRASE)
    except wallet.BackupError:
        return True
    return False


def main():
    checks = []

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "wallet key-material byte sizes pinned to runtime crypto formats",
        wallet.ED25519_PRIVATE_KEY_BYTES == 32
        and wallet.ML_DSA_PUBLIC_KEY_BYTES == 1312
        and wallet.ML_DSA_SECRET_KEY_BYTES == 2560,
    )

    ident = wallet.WalletIdentity()
    backup = wallet.export_backup(ident, PASSPHRASE)
    restored = wallet.restore_backup(backup, PASSPHRASE)
    green(
        "canonical encrypted backup round-trip preserves wallet identity",
        wallet._raw_ed_private(restored) == wallet._raw_ed_private(ident)
        and restored.ml_public_key == ident.ml_public_key
        and restored.ml_secret_key == ident.ml_secret_key
        and restored.address_n == ident.address_n
        and restored.address_m == ident.address_m
        and restored.address_h == ident.address_h,
    )

    material = canonical_material(ident)
    unknown = dict(material)
    unknown["extra"] = "x"
    green(
        "authenticated inner material rejects unknown fields",
        rejected(authenticated_backup_with_material(backup, PASSPHRASE, unknown)),
    )

    missing = dict(material)
    missing.pop("ml_secret")
    green(
        "authenticated inner material rejects missing fields",
        rejected(authenticated_backup_with_material(backup, PASSPHRASE, missing)),
    )

    type_cases = []
    for field in ("ed_private", "ml_public", "ml_secret"):
        bad = dict(material)
        bad[field] = 0
        type_cases.append(
            rejected(authenticated_backup_with_material(backup, PASSPHRASE, bad))
        )
    green("authenticated inner key fields require exact strings", all(type_cases))

    bad_b64 = dict(material)
    bad_b64["ml_public"] = "!" * 16
    green(
        "authenticated inner material rejects malformed base64",
        rejected(authenticated_backup_with_material(backup, PASSPHRASE, bad_b64)),
    )

    ed_lengths = []
    for size in (31, 33):
        bad = dict(material)
        bad["ed_private"] = base64.b64encode(b"E" * size).decode("ascii")
        ed_lengths.append(
            rejected(authenticated_backup_with_material(backup, PASSPHRASE, bad))
        )
    green("Ed25519 private key length is exact before constructor", all(ed_lengths))

    ml_pub_lengths = []
    for size in (
        wallet.ML_DSA_PUBLIC_KEY_BYTES - 1,
        wallet.ML_DSA_PUBLIC_KEY_BYTES + 1,
    ):
        bad = dict(material)
        bad["ml_public"] = base64.b64encode(b"P" * size).decode("ascii")
        ml_pub_lengths.append(
            rejected(authenticated_backup_with_material(backup, PASSPHRASE, bad))
        )
    green(
        "ML-DSA public key length is exact before keypair validation",
        all(ml_pub_lengths),
    )

    ml_sec_lengths = []
    for size in (
        wallet.ML_DSA_SECRET_KEY_BYTES - 1,
        wallet.ML_DSA_SECRET_KEY_BYTES + 1,
    ):
        bad = dict(material)
        bad["ml_secret"] = base64.b64encode(b"K" * size).decode("ascii")
        ml_sec_lengths.append(
            rejected(authenticated_backup_with_material(backup, PASSPHRASE, bad))
        )
    green(
        "ML-DSA secret key length is exact before keypair validation",
        all(ml_sec_lengths),
    )

    dup = (
        '{"ed_private":'
        + json.dumps(material["ed_private"])
        + ',"ed_private":'
        + json.dumps(material["ed_private"])
        + ',"ml_public":'
        + json.dumps(material["ml_public"])
        + ',"ml_secret":'
        + json.dumps(material["ml_secret"])
        + "}"
    ).encode("utf-8")
    green(
        "authenticated inner material rejects duplicate JSON keys",
        rejected(authenticated_backup_with_plain(backup, PASSPHRASE, dup)),
    )

    malformed = b'{"ed_private":'
    green(
        "authenticated malformed inner JSON fails closed after successful decrypt",
        rejected(authenticated_backup_with_plain(backup, PASSPHRASE, malformed)),
    )

    exact = authenticated_backup_with_material(backup, PASSPHRASE, material)
    exact_restored = wallet.restore_backup(exact, PASSPHRASE)
    green(
        "exact authenticated material remains accepted",
        exact_restored.ml_public_key == ident.ml_public_key
        and exact_restored.ml_secret_key == ident.ml_secret_key,
    )

    other = wallet.WalletIdentity()
    mismatched = dict(material)
    mismatched["ml_secret"] = base64.b64encode(other.ml_secret_key).decode("ascii")
    green(
        "length-correct mismatched ML-DSA public and secret keys are rejected",
        rejected(authenticated_backup_with_material(backup, PASSPHRASE, mismatched)),
    )

    message = hashlib.sha256(
        b"axven-wallet-backup-mldsa-keypair-v1|" + ident.ml_public_key
    ).digest()
    signature = axven._mldsa().sign(ident.ml_secret_key, message)
    green(
        "canonical restored ML-DSA keypair remains cryptographically usable",
        bool(axven._mldsa().verify(ident.ml_public_key, message, signature)),
    )

    validator_src = inspect.getsource(wallet._validated_backup_material)
    pair_src = inspect.getsource(wallet._validate_mldsa_keypair)
    restore_src = inspect.getsource(wallet.restore_backup)
    green(
        "production validator enforces exact fields strict decoding and key lengths",
        "set(material) != expected" in validator_src
        and "validate=True" in validator_src
        and "ED25519_PRIVATE_KEY_BYTES" in validator_src
        and "ML_DSA_PUBLIC_KEY_BYTES" in validator_src
        and "ML_DSA_SECRET_KEY_BYTES" in validator_src,
    )
    green(
        "production ML-DSA keypair validator signs and verifies a domain-separated probe",
        "axven-wallet-backup-mldsa-keypair-v1|" in pair_src
        and ".sign(ml_sec, message)" in pair_src
        and ".verify(ml_pub, message, signature)" in pair_src,
    )
    green(
        "restore preserves SEC-128 preflight then rejects duplicate keys before constructors",
        restore_src.index("_preflight_backup_json_nesting(plain)")
        < restore_src.index("json.loads(")
        < restore_src.index("object_pairs_hook=_reject_duplicate_backup_material_keys")
        < restore_src.index("_validated_backup_material(material)")
        < restore_src.index("_validate_mldsa_keypair(ml_pub, ml_sec)")
        < restore_src.index("Ed25519PrivateKey.from_private_bytes"),
    )

    green(
        "wallet material hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-129 wallet inner material canonicality: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
SPEC.write_text(spec, encoding="utf-8", newline="\n")

if WORKFLOW.exists():
    WORKFLOW.unlink()
if SELF.exists():
    SELF.unlink()

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for rel in ("wallet.py", SPEC.name):
    data = (ROOT / rel).read_bytes()
    manifest["files"][rel] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
