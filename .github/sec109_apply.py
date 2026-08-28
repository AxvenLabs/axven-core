#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

wallet_path = Path("wallet.py")
source = wallet_path.read_text(encoding="utf-8")

old_imports = '''import json
import os
from cryptography.hazmat.primitives import serialization
'''
new_imports = '''import json
import os
import tempfile
from cryptography.hazmat.primitives import serialization
'''
if source.count(old_imports) != 1:
    raise SystemExit("SEC-109 wallet import target mismatch")
source = source.replace(old_imports, new_imports)

old_save = '''def save_backup_file(identity, path, passphrase: str):
    data = export_backup(identity, passphrase)
    path = os.fspath(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, sort_keys=True, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
'''
new_save = '''def save_backup_file(identity, path, passphrase: str):
    data = export_backup(identity, passphrase)
    path = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(path) or os.curdir
    is_bytes_path = isinstance(path, bytes)
    prefix = b".axven-wallet-" if is_bytes_path else ".axven-wallet-"
    suffix = b".tmp" if is_bytes_path else ".tmp"
    fd = None
    tmp = None
    try:
        # mkstemp creates a random, exclusive file in the destination
        # directory, preventing predictable-temp symlink clobber attacks.
        fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=parent)
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        f = os.fdopen(fd, "w", encoding="utf-8")
        fd = None
        with f:
            json.dump(data, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        if fd is not None:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
'''
if source.count(old_save) != 1:
    raise SystemExit("SEC-109 wallet save target mismatch")
source = source.replace(old_save, new_save)
wallet_path.write_text(source, encoding="utf-8", newline="\n")

spec = '''#!/usr/bin/env python3
"""SEC-109 secure atomic wallet-backup write contract."""

import os
import stat
import tempfile
from pathlib import Path

import wallet


def same_identity(a, b):
    return (
        a.address_n == b.address_n
        and a.address_m == b.address_m
        and a.address_h == b.address_h
    )


def main():
    checks = 0
    identity = wallet.WalletIdentity()
    passphrase = "sec109-correct-horse-battery-staple"

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "wallet-backup.json"
        predictable = Path(str(target) + ".tmp")
        sentinel = "SEC109-PREDICTABLE-TEMP-MUST-NOT-BE-TOUCHED"
        predictable.write_text(sentinel, encoding="utf-8")

        wallet.save_backup_file(identity, target, passphrase)
        restored = wallet.load_backup_file(target, passphrase)
        assert same_identity(identity, restored)
        checks += 1
        print("[GREEN] canonical encrypted backup round-trip preserved")

        assert predictable.read_text(encoding="utf-8") == sentinel
        checks += 1
        print("[GREEN] predictable legacy .tmp path remains untouched")

        leftovers = [p.name for p in root.iterdir() if p.name.startswith(".axven-wallet-")]
        assert leftovers == []
        checks += 1
        print("[GREEN] successful atomic write leaves no random temp artifact")

        failure_target = root / "failed-backup.json"
        before = {p.name for p in root.iterdir()}
        original_dump = wallet.json.dump
        def fail_dump(*args, **kwargs):
            raise RuntimeError("SEC-109 injected write failure")
        wallet.json.dump = fail_dump
        try:
            try:
                wallet.save_backup_file(identity, failure_target, passphrase)
            except RuntimeError as exc:
                assert "SEC-109 injected write failure" in str(exc)
            else:
                raise AssertionError("injected backup write failure was swallowed")
        finally:
            wallet.json.dump = original_dump
        after = {p.name for p in root.iterdir()}
        assert not failure_target.exists()
        assert after == before
        checks += 1
        print("[GREEN] failed backup write cleans its exclusive temp file")

        if os.name == "posix":
            mode = stat.S_IMODE(target.stat().st_mode)
            assert mode & 0o077 == 0, oct(mode)
        else:
            source = Path(wallet.__file__).read_text(encoding="utf-8")
            assert "os.fchmod(fd, 0o600)" in source
        checks += 1
        print("[GREEN] backup file permission contract is owner-only on POSIX")

        source = Path(wallet.__file__).read_text(encoding="utf-8")
        assert "tempfile.mkstemp" in source
        assert "tmp = path + \".tmp\"" not in source
        assert "os.replace(tmp, path)" in source
        assert "os.unlink(tmp)" in source
        checks += 1
        print("[GREEN] secure random atomic-write primitives pinned in production")

        if os.name == "posix":
            victim = root / "victim.txt"
            victim.write_text("SEC109-VICTIM", encoding="utf-8")
            symlink_target = root / "symlink-backup.json"
            os.symlink(victim, symlink_target)
            wallet.save_backup_file(identity, symlink_target, passphrase)
            assert victim.read_text(encoding="utf-8") == "SEC109-VICTIM"
            assert not symlink_target.is_symlink()
            assert same_identity(identity, wallet.load_backup_file(symlink_target, passphrase))
        checks += 1
        print("[GREEN] destination replacement does not follow a pre-existing symlink")

    print(f"SEC-109 secure wallet backup atomic write: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = Path("security_sec109_wallet_backup_atomic_write_spec.py")
spec_path.write_text(spec, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("wallet.py", spec_path.name):
    data = Path(name).read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest["files"] = dict(sorted(manifest["files"].items()))
manifest_path.write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
    newline="\n",
)
