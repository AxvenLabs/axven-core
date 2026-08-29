#!/usr/bin/env python3
"""SEC-174: persisted chain state must be read through a bound regular file."""
from __future__ import annotations

import inspect
import os
import stat
import tempfile
import types

import axven


def rejected(fn, exc_type=ValueError):
    try:
        fn()
    except exc_type:
        return True
    return False


def main():
    checks = []
    def ok(name, value):
        assert value, name
        checks.append(name)

    with tempfile.TemporaryDirectory(prefix="axven_sec174_") as root:
        store = axven.StateStore(os.path.join(root, "roundtrip"))
        chain = axven.Blockchain()
        store.persist(chain)
        loaded = store.load()
        ok("canonical roundtrip", loaded.tip.hash() == chain.tip.hash())
        ok("roundtrip validates", loaded.validate())

        missing = axven.StateStore(os.path.join(root, "missing"))
        ok("missing state remains missing", rejected(missing.load, FileNotFoundError))

        nonregular = axven.StateStore(os.path.join(root, "nonregular"))
        nonregular.path.mkdir()
        ok("directory state rejected", rejected(nonregular.load))

        hard = axven.StateStore(os.path.join(root, "hardlink"))
        hard.persist(axven.Blockchain())
        alias = hard.directory / "chain.alias"
        try:
            os.link(hard.path, alias)
        except OSError:
            hardlink_supported = False
        else:
            hardlink_supported = True
            ok("hardlinked state rejected", rejected(hard.load))
            alias.unlink()
        if not hardlink_supported:
            helper_source = inspect.getsource(axven._read_secure_chain_state_file)
            ok("hardlink guard present", "st_nlink" in helper_source)

        sym = axven.StateStore(os.path.join(root, "symlink"))
        sym.persist(axven.Blockchain())
        real = sym.directory / "chain.real"
        sym.path.replace(real)
        try:
            os.symlink(real.name, sym.path)
        except OSError:
            symlink_supported = False
            real.replace(sym.path)
        else:
            symlink_supported = True
            ok("symlink state rejected", rejected(sym.load))
            sym.path.unlink()
            real.replace(sym.path)
        if not symlink_supported:
            helper_source = inspect.getsource(axven._read_secure_chain_state_file)
            ok("symlink guard present", "S_ISLNK" in helper_source)

        race = axven.StateStore(os.path.join(root, "identity"))
        race.persist(axven.Blockchain())
        real_lstat = axven.os.lstat
        def mismatched_lstat(path):
            current = real_lstat(path)
            if os.fspath(path) == os.fspath(race.path):
                return types.SimpleNamespace(
                    st_mode=current.st_mode,
                    st_nlink=current.st_nlink,
                    st_dev=current.st_dev,
                    st_ino=current.st_ino + 1,
                )
            return current
        axven.os.lstat = mismatched_lstat
        try:
            ok("path replacement race rejected", rejected(race.load))
        finally:
            axven.os.lstat = real_lstat

    helper_source = inspect.getsource(axven._read_secure_chain_state_file)
    load_source = inspect.getsource(axven.StateStore.load)
    ok("load uses secure reader", "_read_secure_chain_state_file" in load_source)
    ok("legacy read_bytes removed", ".read_bytes()" not in load_source)
    ok("lstat guard", "os.lstat" in helper_source)
    ok("descriptor identity guard", "os.fstat" in helper_source and "st_ino" in helper_source)
    ok("regular-file guard", "S_ISREG" in helper_source)
    ok("single-link guard", "st_nlink" in helper_source)
    ok("no-follow requested", "O_NOFOLLOW" in helper_source)
    ok("chain id unchanged", axven.CHAIN_ID == "axven-devnet-2")
    ok("config fingerprint unchanged", axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    ok("genesis unchanged", axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")

    print(f"SEC-174 chain-state file integrity: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
