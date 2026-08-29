#!/usr/bin/env python3
"""SEC-168 RPC token bootstrap fail-closed regression contract."""
import inspect
import os
import tempfile
from pathlib import Path

import axven
import axven_core
import datadir
from datadir import DataDir


def main():
    checks=[]
    def green(name,condition):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    # Normal creation remains canonical.
    with tempfile.TemporaryDirectory(prefix="axven_sec168_normal_") as td:
        dd=DataDir(td)
        token=dd.load_or_create_rpc_token()
        green(
            "normal RPC token bootstrap returns canonical 256-bit hex",
            type(token) is str and len(token)==64
            and all(ch in "0123456789abcdef" for ch in token)
            and dd.load_rpc_token()==token,
        )

    # Simulate: initial load sees no file; O_EXCL says another creator won;
    # before the retry read, the path is gone. This must never return None.
    with tempfile.TemporaryDirectory(prefix="axven_sec168_lost_") as td:
        dd=DataDir(td)
        original_open=datadir.os.open
        def lost_race(path,flags,mode=0o777):
            if (
                os.fspath(path)==os.fspath(dd.rpc_token_file)
                and flags & os.O_CREAT and flags & os.O_EXCL
            ):
                raise FileExistsError(os.fspath(path))
            return original_open(path,flags,mode)
        datadir.os.open=lost_race
        try:
            try:
                dd.load_or_create_rpc_token()
            except RuntimeError as exc:
                failed_closed="creation race" in str(exc)
            else:
                failed_closed=False
        finally:
            datadir.os.open=original_open
        green(
            "vanished competing token fails closed instead of returning None",
            failed_closed,
        )

    # Simulate a valid concurrent creator appearing exactly at O_EXCL.
    with tempfile.TemporaryDirectory(prefix="axven_sec168_winner_") as td:
        dd=DataDir(td)
        winner="ab"*32
        original_open=datadir.os.open
        injected=[False]
        def winning_race(path,flags,mode=0o777):
            if (
                not injected[0]
                and os.fspath(path)==os.fspath(dd.rpc_token_file)
                and flags & os.O_CREAT and flags & os.O_EXCL
            ):
                injected[0]=True
                Path(path).write_bytes(winner.encode("ascii")+b"\n")
                if os.name=="posix":
                    os.chmod(path,0o600)
                raise FileExistsError(os.fspath(path))
            return original_open(path,flags,mode)
        datadir.os.open=winning_race
        try:
            observed=dd.load_or_create_rpc_token()
        finally:
            datadir.os.open=original_open
        green(
            "valid concurrent creator token is adopted exactly",
            observed==winner and dd.load_rpc_token()==winner,
        )

    source=inspect.getsource(datadir.DataDir.load_or_create_rpc_token)
    green(
        "token creation retry has an explicit no-None fail-closed guard",
        "existing=self.load_rpc_token()" in source
        and "if existing is None:" in source
        and "raise RuntimeError" in source,
    )
    daemon_source=inspect.getsource(axven_core.main)
    green(
        "production daemon refuses to start RPC without an auth token",
        "rpc_token=dd.load_or_create_rpc_token()" in daemon_source
        and "if rpc_token is None:" in daemon_source
        and "auth_token=rpc_token" in daemon_source,
    )
    green(
        "RPC bootstrap hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID=="axven-devnet-2"
        and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )
    print(f"SEC-168 RPC token bootstrap fail closed: {len(checks)}/{len(checks)} GREEN")

if __name__=="__main__":
    main()
