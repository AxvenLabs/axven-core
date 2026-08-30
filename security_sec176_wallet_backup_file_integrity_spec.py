#!/usr/bin/env python3
"""SEC-176: encrypted wallet backup reads must bind to safe filesystem metadata."""
from __future__ import annotations

import inspect
import os
import tempfile
from pathlib import Path

import axven
import wallet


def rejected(fn):
    try:
        fn()
    except wallet.BackupError:
        return True
    return False


def main():
    checks=[]
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print(f"[GREEN] {name}")

    with tempfile.TemporaryDirectory(prefix="axven_sec176_") as td:
        root=Path(td)
        path=root/"wallet.json"
        passphrase="sec176-passphrase"
        ident=wallet.WalletIdentity()
        wallet.save_backup_file(ident,path,passphrase)
        loaded=wallet.load_backup_file(path,passphrase)
        green("canonical encrypted wallet remains readable", loaded.address_h == ident.address_h)

        original=path.read_bytes()

        alias=root/"wallet-hardlink.json"
        hardlink_supported=True
        try:
            os.link(path,alias)
        except OSError:
            hardlink_supported=False
        if hardlink_supported:
            green("multiply-linked wallet backup rejected", rejected(lambda: wallet.load_backup_file(path,passphrase)))
            alias.unlink()
            green("wallet readable after hardlink removal", wallet.load_backup_file(path,passphrase).address_h == ident.address_h)
        else:
            green("hardlink-count guard present", "st_nlink" in inspect.getsource(wallet._read_secure_backup_file))

        path.unlink()
        path.mkdir()
        green("non-regular wallet path rejected", rejected(lambda: wallet.load_backup_file(path,passphrase)))
        path.rmdir()
        path.write_bytes(original)
        if os.name == "posix": os.chmod(path,0o600)

        target=root/"wallet-target.json"
        target.write_bytes(original)
        if os.name == "posix": os.chmod(target,0o600)
        path.unlink()
        symlink_supported=True
        try:
            os.symlink(target,path)
        except OSError:
            symlink_supported=False
        if symlink_supported:
            green("symlink wallet path rejected", rejected(lambda: wallet.load_backup_file(path,passphrase)))
            path.unlink()
        else:
            green("symlink rejection guard present", "S_ISLNK" in inspect.getsource(wallet._read_secure_backup_file))
        path.write_bytes(original)
        if os.name == "posix": os.chmod(path,0o600)

        if os.name == "posix":
            os.chmod(path,0o644)
            green("group/world-readable wallet rejected", rejected(lambda: wallet.load_backup_file(path,passphrase)))
            os.chmod(path,0o600)

        real_open=wallet.os.open
        replacement=root/"replacement.json"
        replacement.write_bytes(original)
        if os.name == "posix": os.chmod(replacement,0o600)
        swapped={"done":False}
        def racing_open(name,flags,*args,**kwargs):
            if os.fspath(name) == os.fspath(path) and not swapped["done"]:
                swapped["done"]=True
                os.replace(replacement,path)
            return real_open(name,flags,*args,**kwargs)
        wallet.os.open=racing_open
        try:
            green("path identity replacement rejected", rejected(lambda: wallet.load_backup_file(path,passphrase)))
        finally:
            wallet.os.open=real_open

        src=inspect.getsource(wallet._read_secure_backup_file)
        green("reader lstat-binds path before open", "os.lstat" in src)
        green("reader requests no-follow where available", "O_NOFOLLOW" in src)
        green("reader validates opened descriptor", "os.fstat" in src and "stat.S_ISREG" in src)
        green("reader compares filesystem identity", "st_dev" in src and "st_ino" in src)
        green("reader enforces bounded read", "MAX_BACKUP_FILE_BYTES + 1" in src)
        green("reader checks POSIX owner-only metadata", "0o077" in src and "getuid" in src)

    green("chain id unchanged", axven.CHAIN_ID == "axven-devnet-2")
    green("config fingerprint unchanged", axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    green("genesis unchanged", axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
    print(f"SEC-176 wallet backup file integrity: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
