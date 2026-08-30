#!/usr/bin/env python3
"""SEC-184: chain-state child directory must be owner-controlled and non-redirectable."""
from __future__ import annotations

import inspect
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import axven
import datadir


def _run_as_posix(fn):
    original_name=axven.os.name
    had_getuid=hasattr(axven.os,"getuid")
    original_getuid=getattr(axven.os,"getuid",None)
    try:
        axven.os.name="posix"
        axven.os.getuid=lambda:4242
        return fn()
    finally:
        axven.os.name=original_name
        if had_getuid:
            axven.os.getuid=original_getuid
        else:
            delattr(axven.os,"getuid")


def _meta(mode,uid=4242):
    return SimpleNamespace(st_mode=mode,st_uid=uid)


def _reject_meta(metadata):
    def attempt():
        try:
            axven._validate_chain_state_directory_metadata(metadata)
        except ValueError:
            return True
        return False
    return _run_as_posix(attempt)


def rejected(fn):
    try:
        fn()
    except (ValueError,FileExistsError,NotADirectoryError):
        return True
    return False


def main():
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name)
        print(f"[GREEN] {name}")

    green("owner-controlled POSIX chain directory accepted",
          _run_as_posix(lambda: bool(axven._validate_chain_state_directory_metadata(_meta(stat.S_IFDIR|0o700)))))
    green("group-writable chain directory rejected",
          _reject_meta(_meta(stat.S_IFDIR|0o720)))
    green("world-writable chain directory rejected",
          _reject_meta(_meta(stat.S_IFDIR|0o702)))
    green("foreign-owned chain directory rejected",
          _reject_meta(_meta(stat.S_IFDIR|0o700,9999)))
    green("non-directory chain path rejected",
          _reject_meta(_meta(stat.S_IFREG|0o600)))

    with tempfile.TemporaryDirectory(prefix="axven_sec184_") as td:
        root=Path(td)
        fresh=axven.StateStore(root/"fresh")
        green("fresh chain directory created",fresh.directory.is_dir())
        if os.name=="posix":
            green("fresh chain directory is not group/world writable",
                  not (fresh.directory.stat().st_mode & 0o022))

        target=root/"target"
        target.mkdir()
        link=root/"chain-link"
        symlink_supported=True
        try:
            os.symlink(target,link,target_is_directory=True)
        except OSError:
            symlink_supported=False
        if symlink_supported:
            green("symlink chain directory rejected",rejected(lambda:axven.StateStore(link)))
        else:
            src=inspect.getsource(axven._validate_chain_state_directory)
            green("symlink directory guard present","S_ISLNK" in src and "os.lstat" in src)

        regular=root/"not-a-directory"
        regular.write_text("x",encoding="utf-8")
        green("regular-file chain directory rejected",rejected(lambda:axven.StateStore(regular)))

        dd=datadir.DataDir(root/"data")
        first=dd.load_chain()
        green("first-run genesis behavior preserved",first.tip.hash()==axven._genesis().hash())
        green("first-run load creates validated chain directory",dd.chain_dir.is_dir())

        # A dangling chain.json symlink must not be treated as an absent first-run
        # file by Path.exists(); the secure file reader must see and reject it.
        dangling=dd.chain_dir/"missing-target.json"
        symlink_file_supported=True
        try:
            os.symlink(dangling,dd.chain_dir/"chain.json")
        except OSError:
            symlink_file_supported=False
        if symlink_file_supported:
            green("dangling chain-state symlink rejected",rejected(dd.load_chain))
            (dd.chain_dir/"chain.json").unlink()
        else:
            load_src=inspect.getsource(datadir.DataDir.load_chain)
            green("load_chain uses lstat presence test","os.lstat" in load_src)

    helper_src=inspect.getsource(axven._validate_chain_state_directory)
    init_src=inspect.getsource(axven.StateStore.__init__)
    load_src=inspect.getsource(datadir.DataDir.load_chain)
    green("chain directory lstat guard present","os.lstat" in helper_src and "S_ISLNK" in helper_src)
    green("StateStore validates directory before child path publication",
          init_src.index("_validate_chain_state_directory") < init_src.index("self.path"))
    green("load_chain constructs StateStore before state presence decision",
          load_src.index("StateStore") < load_src.index("os.lstat"))
    green("legacy Path.exists bypass removed","chain_file.exists()" not in load_src)
    green("chain id unchanged",axven.CHAIN_ID=="axven-devnet-2")
    green("config fingerprint unchanged",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    green("genesis unchanged",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
    print(f"SEC-184 chain directory integrity: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
