#!/usr/bin/env python3
"""SEC-177: persisted peer configuration must be read through a bound regular file."""
from __future__ import annotations

import inspect
import os
import tempfile
from pathlib import Path

import axven
import datadir


def rejected(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


def main():
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name)
        print(f"[GREEN] {name}")

    with tempfile.TemporaryDirectory(prefix="axven_sec177_") as td:
        root=Path(td)
        dd=datadir.DataDir(root)
        peers=[("127.0.0.1",18444),("localhost",18445)]
        dd.save_peers(peers)
        green("canonical peer config remains readable",dd.load_peers()==peers)

        dd.peer_file.unlink()
        green("missing peer config remains empty",dd.load_peers()==[])
        dd.save_peers(peers)
        original=dd.peer_file.read_bytes()

        alias=root/"peers-hardlink.json"
        hardlink_supported=True
        try:
            os.link(dd.peer_file,alias)
        except OSError:
            hardlink_supported=False
        if hardlink_supported:
            green("multiply-linked peer config rejected",rejected(dd.load_peers))
            alias.unlink()
            green("peer config readable after hardlink removal",dd.load_peers()==peers)
        else:
            green("hardlink-count guard present","st_nlink" in inspect.getsource(datadir._read_secure_peer_config_file))

        dd.peer_file.unlink()
        dd.peer_file.mkdir()
        green("non-regular peer config rejected",rejected(dd.load_peers))
        dd.peer_file.rmdir()
        dd.peer_file.write_bytes(original)
        if os.name=="posix": os.chmod(dd.peer_file,0o600)

        target=root/"peers-target.json"
        target.write_bytes(original)
        if os.name=="posix": os.chmod(target,0o600)
        dd.peer_file.unlink()
        symlink_supported=True
        try:
            os.symlink(target,dd.peer_file)
        except OSError:
            symlink_supported=False
        if symlink_supported:
            green("symlink peer config rejected",rejected(dd.load_peers))
            dd.peer_file.unlink()
            dangling=root/"missing-peer-target.json"
            os.symlink(dangling,dd.peer_file)
            green("dangling symlink peer config rejected",rejected(dd.load_peers))
            dd.peer_file.unlink()
        else:
            green("symlink rejection guard present","S_ISLNK" in inspect.getsource(datadir._read_secure_peer_config_file))
        dd.peer_file.write_bytes(original)
        if os.name=="posix": os.chmod(dd.peer_file,0o600)

        if os.name=="posix":
            os.chmod(dd.peer_file,0o644)
            green("group/world-readable peer config rejected",rejected(dd.load_peers))
            os.chmod(dd.peer_file,0o600)

        replacement=root/"peers-replacement.json"
        replacement.write_bytes(original)
        if os.name=="posix": os.chmod(replacement,0o600)
        real_open=datadir.os.open
        swapped={"done":False}
        def racing_open(name,flags,*args,**kwargs):
            if os.fspath(name)==os.fspath(dd.peer_file) and not swapped["done"]:
                swapped["done"]=True
                os.replace(replacement,dd.peer_file)
            return real_open(name,flags,*args,**kwargs)
        datadir.os.open=racing_open
        try:
            green("peer config path replacement rejected",rejected(dd.load_peers))
        finally:
            datadir.os.open=real_open

    src=inspect.getsource(datadir._read_secure_peer_config_file)
    load_src=inspect.getsource(datadir.DataDir.load_peers)
    green("load_peers uses secure reader","_read_secure_peer_config_file" in load_src)
    green("legacy exists/open path removed","self.peer_file.exists()" not in load_src and "open(self.peer_file" not in load_src)
    green("reader lstat-binds path before open","os.lstat" in src)
    green("reader requests no-follow where available","O_NOFOLLOW" in src)
    green("reader validates opened descriptor","os.fstat" in src and "stat.S_ISREG" in src)
    green("reader compares filesystem identity","st_dev" in src and "st_ino" in src)
    green("reader enforces single link","st_nlink" in src)
    green("reader preserves bounded read","MAX_PEER_CONFIG_BYTES+1" in src)
    green("reader checks POSIX owner-only metadata","0o077" in src and "getuid" in src)
    green("chain id unchanged",axven.CHAIN_ID=="axven-devnet-2")
    green("config fingerprint unchanged",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    green("genesis unchanged",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
    print(f"SEC-177 peer config file integrity: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
