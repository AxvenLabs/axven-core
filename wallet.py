#!/usr/bin/env python3
from __future__ import annotations
import axven
import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
class WalletIdentity:
    def __init__(self,ed_keypair=None,ml_keypair=None):
        if ed_keypair is None:
            ed=axven.Wallet(); self.ed_public_key=ed.public_key; self.ed_private_key=ed.private_key
        else:self.ed_public_key,self.ed_private_key=ed_keypair
        if ml_keypair is None:
            ml=axven.MLDSAWallet(); self.ml_public_key=ml.public_key; self.ml_secret_key=ml._secret
        else:self.ml_public_key,self.ml_secret_key=ml_keypair
        self.address_n=axven.address_from_pubkey(self.ed_public_key); self.address_m=axven.ml_address_from_pubkey(self.ml_public_key); self.address_h=axven.hybrid_address(self.ed_public_key,self.ml_public_key)
    def address_of(self,scheme):
        if scheme==axven.SCHEME_ED25519:return self.address_n
        if scheme==axven.SCHEME_ML_DSA:return self.address_m
        if scheme==axven.SCHEME_HYBRID:return self.address_h
        raise ValueError(f"unknown scheme: {scheme}")
_CHANGE_PRIORITY={axven.SCHEME_ED25519:(axven.SCHEME_ED25519,axven.SCHEME_ML_DSA),axven.SCHEME_ML_DSA:(axven.SCHEME_ML_DSA,),axven.SCHEME_HYBRID:(axven.SCHEME_HYBRID,axven.SCHEME_ML_DSA)}
def change_address(identity,input_scheme,height):
    if input_scheme not in _CHANGE_PRIORITY: raise ValueError(f"unknown input scheme: {input_scheme}")
    for scheme in _CHANGE_PRIORITY[input_scheme]:
        addr=identity.address_of(scheme)
        if axven.output_scheme_allowed(addr,height): return addr
    raise ValueError("no consensus-allowed change address")

# ---------------------------------------------------------------------------
# Rebuild checkpoint 1: W-002 completion + W-003 pending integration
# ---------------------------------------------------------------------------
class InsufficientFunds(ValueError):
    pass


class PendingTracker:
    def __init__(self):
        self._by_txid = {}
        self._reserved = set()

    @staticmethod
    def _norm(op):
        if isinstance(op, str):
            txid, idx = op.rsplit(":", 1)
            return (txid, int(idx))
        return (op[0], int(op[1]))

    def reserve(self, txid, outpoints):
        ops = {self._norm(op) for op in outpoints}
        # replace an existing reservation atomically
        self.release(txid)
        self._by_txid[txid] = ops
        self._reserved.update(ops)

    def release(self, txid):
        ops = self._by_txid.pop(txid, set())
        for op in ops:
            if not any(op in other for other in self._by_txid.values()):
                self._reserved.discard(op)

    def is_reserved(self, outpoint):
        return self._norm(outpoint) in self._reserved

    def reconcile(self, mempool):
        live = set(getattr(mempool, "txs", {}).keys())
        for txid in list(self._by_txid):
            if txid not in live:
                self.release(txid)


def select_coins(chain, identity, scheme, amount, fee, tracker=None):
    if amount < 0 or fee < 0:
        raise ValueError("amount/fee must be non-negative")
    target = amount + fee
    coins = list(chain.spendable(identity.address_of(scheme)))
    if tracker is not None:
        coins = [c for c in coins if not tracker.is_reserved((c[0], c[1]))]
    coins.sort(key=lambda c: (-c[2], c[0], c[1]))
    selected = []
    total = 0
    for coin in coins:
        selected.append(coin)
        total += coin[2]
        if total >= target:
            return selected
    raise InsufficientFunds(f"need {target}, only {total} spendable")


def build_transaction(chain, identity, input_scheme, recipient, amount, fee, height=None, tracker=None):
    height = chain.tip.height + 1 if height is None else height
    if not axven.output_scheme_allowed(recipient, height):
        raise ValueError(f"recipient scheme forbidden at height {height}")
    coins = select_coins(chain, identity, input_scheme, amount, fee, tracker=tracker)
    total = sum(c[2] for c in coins)
    inputs = [axven.TxInput(txid, idx) for txid, idx, _ in coins]
    outputs = [axven.TxOutput(amount, recipient)]
    change = total - amount - fee
    if change:
        outputs.append(axven.TxOutput(change, change_address(identity, input_scheme, height)))
    return axven.Transaction(inputs, outputs)


def sign_transaction(identity, tx, scheme):
    if scheme == axven.SCHEME_ED25519:
        signer = axven.Wallet(identity.ed_private_key)
    elif scheme == axven.SCHEME_ML_DSA:
        signer = axven.MLDSAWallet((identity.ml_public_key, identity.ml_secret_key))
    elif scheme == axven.SCHEME_HYBRID:
        ed = axven.Wallet(identity.ed_private_key)
        ml = axven.MLDSAWallet((identity.ml_public_key, identity.ml_secret_key))
        signer = axven.HybridWallet(ed, ml)
    else:
        raise ValueError(f"unknown scheme: {scheme}")
    signed = [signer.sign_input(tx, i) for i in range(len(tx.inputs))]
    return axven.Transaction(signed, tx.outputs, tx.coinbase_height)


# ---------------------------------------------------------------------------
# Checkpoint 7: encrypted wallet persistence / backup
# ---------------------------------------------------------------------------
class BackupError(ValueError):
    pass

BACKUP_VERSION = 1
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_PARAMS = {"n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P, "dklen": _SCRYPT_DKLEN}
MAX_BACKUP_FILE_BYTES = 64 * 1024
MAX_BACKUP_CIPHERTEXT_BYTES = 16 * 1024
ED25519_PRIVATE_KEY_BYTES = 32
ML_DSA_PUBLIC_KEY_BYTES = 1312
ML_DSA_SECRET_KEY_BYTES = 2560
_MAX_CIPHERTEXT_B64_CHARS = 4 * ((MAX_BACKUP_CIPHERTEXT_BYTES + 2) // 3)

def _validated_scrypt_params(value):
    if type(value) is not dict or set(value) != set(_SCRYPT_PARAMS):
        raise BackupError("unsupported scrypt parameters")
    for name, expected in _SCRYPT_PARAMS.items():
        if type(value[name]) is not int or value[name] != expected:
            raise BackupError("unsupported scrypt parameters")
    return _SCRYPT_PARAMS

def _validated_backup_envelope(backup, passphrase):
    if type(backup) is not dict:
        raise BackupError("backup must be an object")
    if type(passphrase) is not str or not passphrase:
        raise BackupError("non-empty passphrase required")
    if type(backup.get("version")) is not int or backup.get("version") != BACKUP_VERSION:
        raise BackupError("unsupported backup version")
    if backup.get("kdf") != "scrypt" or backup.get("cipher") != "aes-256-gcm":
        raise BackupError("unsupported backup crypto")
    kp = _validated_scrypt_params(backup.get("kdf_params"))

    salt_text = backup.get("salt")
    nonce_text = backup.get("nonce")
    cipher_text = backup.get("ciphertext")
    checksum = backup.get("checksum")
    if type(salt_text) is not str or len(salt_text) != 24:
        raise BackupError("invalid backup salt")
    if type(nonce_text) is not str or len(nonce_text) != 16:
        raise BackupError("invalid backup nonce")
    if (type(cipher_text) is not str or not cipher_text
            or len(cipher_text) > _MAX_CIPHERTEXT_B64_CHARS):
        raise BackupError("backup ciphertext too large or invalid")
    if (type(checksum) is not str or len(checksum) != 64
            or any(c not in "0123456789abcdef" for c in checksum)):
        raise BackupError("invalid backup checksum")
    return kp, salt_text, nonce_text, cipher_text, checksum

def _reject_duplicate_backup_material_keys(pairs):
    out={}
    for key,value in pairs:
        if key in out:
            raise BackupError("duplicate backup material field")
        out[key]=value
    return out


def _validated_backup_material(plain):
    try:
        material=json.loads(
            plain,
            object_pairs_hook=_reject_duplicate_backup_material_keys,
        )
    except BackupError:
        raise
    except (UnicodeError,json.JSONDecodeError) as exc:
        raise BackupError("invalid backup material JSON") from exc
    expected={"ed_private","ml_public","ml_secret"}
    if type(material) is not dict or set(material) != expected:
        raise BackupError("invalid backup material fields")
    values=[]
    for name in ("ed_private","ml_public","ml_secret"):
        text=material[name]
        if type(text) is not str:
            raise BackupError("invalid backup material value")
        try:
            values.append(base64.b64decode(text,validate=True))
        except Exception as exc:
            raise BackupError("invalid backup material encoding") from exc
    ed_raw,ml_pub,ml_sec=values
    if len(ed_raw) != ED25519_PRIVATE_KEY_BYTES:
        raise BackupError("invalid Ed25519 private key length")
    if len(ml_pub) != ML_DSA_PUBLIC_KEY_BYTES:
        raise BackupError("invalid ML-DSA public key length")
    if len(ml_sec) != ML_DSA_SECRET_KEY_BYTES:
        raise BackupError("invalid ML-DSA secret key length")
    return ed_raw,ml_pub,ml_sec


def _raw_ed_private(identity):
    return identity.ed_private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )

def export_backup(identity, passphrase: str):
    if not isinstance(passphrase, str) or not passphrase:
        raise BackupError("non-empty passphrase required")
    material = {
        "ed_private": base64.b64encode(_raw_ed_private(identity)).decode("ascii"),
        "ml_public": base64.b64encode(identity.ml_public_key).decode("ascii"),
        "ml_secret": base64.b64encode(identity.ml_secret_key).decode("ascii"),
    }
    plain = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=_SCRYPT_N,
                         r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    cipher = AESGCM(key).encrypt(nonce, plain, b"axven-wallet-backup-v1")
    return {
        "version": BACKUP_VERSION,
        "kdf": "scrypt",
        "kdf_params": dict(_SCRYPT_PARAMS),
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(cipher).decode("ascii"),
        "checksum": hashlib.sha256(cipher).hexdigest(),
    }

def restore_backup(backup, passphrase: str):
    try:
        kp, salt_text, nonce_text, cipher_text, checksum = _validated_backup_envelope(
            backup, passphrase)
        salt = base64.b64decode(salt_text, validate=True)
        nonce = base64.b64decode(nonce_text, validate=True)
        cipher = base64.b64decode(cipher_text, validate=True)
        if len(salt) != 16:
            raise BackupError("invalid backup salt")
        if len(nonce) != 12:
            raise BackupError("invalid backup nonce")
        if len(cipher) < 16 or len(cipher) > MAX_BACKUP_CIPHERTEXT_BYTES:
            raise BackupError("backup ciphertext too large or invalid")
        if hashlib.sha256(cipher).hexdigest() != checksum:
            raise BackupError("backup checksum mismatch")
        key = hashlib.scrypt(passphrase.encode(), salt=salt, n=kp["n"],
                             r=kp["r"], p=kp["p"], dklen=kp["dklen"])
        plain = AESGCM(key).decrypt(nonce, cipher, b"axven-wallet-backup-v1")
        ed_raw,ml_pub,ml_sec=_validated_backup_material(plain)
        ed_priv = Ed25519PrivateKey.from_private_bytes(ed_raw)
        ed_pub = ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return WalletIdentity(ed_keypair=(ed_pub, ed_priv), ml_keypair=(ml_pub, ml_sec))
    except BackupError:
        raise
    except Exception as e:
        raise BackupError("wrong passphrase or corrupt backup") from e

def save_backup_file(identity, path, passphrase: str):
    data = export_backup(identity, passphrase)
    target = Path(os.fspath(path))
    parent = target.parent if str(target.parent) else Path(".")
    fd = None
    tmp_path = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=str(parent),
            text=True,
        )
        tmp_path = Path(tmp_name)
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            json.dump(data, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
        tmp_path = None
        if os.name == "posix":
            os.chmod(target, 0o600)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

def load_backup_file(path, passphrase: str):
    path = os.fspath(path)
    with open(path, "rb") as f:
        raw = f.read(MAX_BACKUP_FILE_BYTES + 1)
    if len(raw) > MAX_BACKUP_FILE_BYTES:
        raise BackupError("backup file too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as e:
        raise BackupError("corrupt backup file") from e
    return restore_backup(data, passphrase)
