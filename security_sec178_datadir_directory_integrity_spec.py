#!/usr/bin/env python3
"""SEC-178: resolved datadir must be owner-controlled before child paths are trusted."""
from __future__ import annotations

import inspect
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import axven
import datadir


def _metadata(mode, uid):
    return SimpleNamespace(st_mode=mode, st_uid=uid)


def _run_as_posix(fn):
    original_name = datadir.os.name
    had_getuid = hasattr(datadir.os, "getuid")
    original_getuid = getattr(datadir.os, "getuid", None)
    try:
        datadir.os.name = "posix"
        datadir.os.getuid = lambda: 4242
        return fn()
    finally:
        datadir.os.name = original_name
        if had_getuid:
            datadir.os.getuid = original_getuid
        else:
            delattr(datadir.os, "getuid")


def _accept(metadata):
    return _run_as_posix(
        lambda: datadir._validate_datadir_directory_metadata(metadata)
    )


def _reject(metadata):
    def attempt():
        try:
            datadir._validate_datadir_directory_metadata(metadata)
        except ValueError:
            return True
        return False
    return _run_as_posix(attempt)


def main():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "axven-data"
        dd = datadir.DataDir(root)
        assert dd.path == root.resolve()
    print("[GREEN] canonical datadir creation preserved")

    assert _accept(_metadata(stat.S_IFDIR | 0o700, 4242))
    print("[GREEN] owner-controlled POSIX directory accepted")

    assert _reject(_metadata(stat.S_IFDIR | 0o720, 4242))
    print("[GREEN] group-writable datadir rejected")

    assert _reject(_metadata(stat.S_IFDIR | 0o702, 4242))
    print("[GREEN] world-writable datadir rejected")

    assert _reject(_metadata(stat.S_IFDIR | 0o700, 9999))
    print("[GREEN] foreign-owned datadir rejected")

    assert _reject(_metadata(stat.S_IFREG | 0o600, 4242))
    print("[GREEN] non-directory metadata rejected")

    helper_src = inspect.getsource(datadir._validate_datadir_directory)
    assert "os.lstat" in helper_src
    assert "stat.S_ISLNK" in helper_src
    print("[GREEN] datadir path metadata is checked without following symlinks")

    init_src = inspect.getsource(datadir.DataDir.__init__)
    mkdir_at = init_src.index("self.path.mkdir")
    validate_at = init_src.index("_validate_datadir_directory(self.path)")
    child_at = init_src.index("self.chain_dir")
    assert mkdir_at < validate_at < child_at
    print("[GREEN] datadir trust check precedes child lock/state path publication")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    print("[GREEN] canonical chain identity unchanged")

    print("SEC-178 datadir directory integrity: 9/9 GREEN")


if __name__ == "__main__":
    main()
