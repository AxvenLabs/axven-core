#!/usr/bin/env python3
"""SEC-183: chain-state files must remain owner-controlled on POSIX."""
from __future__ import annotations

import inspect
import os
import tempfile
from pathlib import Path

import axven


def rejected(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


def main():
    checks = []

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    with tempfile.TemporaryDirectory(prefix="axven_sec183_") as td:
        store = axven.StateStore(td)
        chain = axven.Blockchain()
        store.persist(chain)
        green("canonical chain state remains readable", store.load().tip.hash() == chain.tip.hash())

        if os.name == "posix":
            mode = store.path.stat().st_mode & 0o777
            green("canonical persistence remains owner-only", mode == 0o600)

            os.chmod(store.path, 0o644)
            green("public read-only chain state remains readable", store.load().tip.hash() == chain.tip.hash())

            os.chmod(store.path, 0o660)
            green("group-writable chain state rejected", rejected(store.load))

            os.chmod(store.path, 0o602)
            green("world-writable chain state rejected", rejected(store.load))

            os.chmod(store.path, 0o600)

    src = inspect.getsource(axven._read_secure_chain_state_file)
    green("path lstat binding preserved", "os.lstat" in src)
    green("no-follow open preserved", "O_NOFOLLOW" in src)
    green("opened descriptor validation preserved", "os.fstat" in src and "stat.S_ISREG" in src)
    green("filesystem identity binding preserved", "st_dev" in src and "st_ino" in src)
    green("single-link guard preserved", "st_nlink" in src)
    green("POSIX write-permission guard present", "0o022" in src)
    green("POSIX owner guard present", "st_uid" in src and "getuid" in src)
    green("chain id unchanged", axven.CHAIN_ID == "axven-devnet-2")
    green("config fingerprint unchanged", axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    green("genesis unchanged", axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
    print(f"SEC-183 chain-state owner permissions: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
