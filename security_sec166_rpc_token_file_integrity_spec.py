#!/usr/bin/env python3
"""SEC-166 RPC token filesystem-integrity regression contract."""
from __future__ import annotations
import inspect,os,stat,tempfile
from pathlib import Path
import axven
import axven_cli
from datadir import DataDir,_read_secure_rpc_token_file


def expect_value_error(fn):
    try:
        fn()
    except (ValueError,axven_cli.RPCClientError):
        return True
    return False


def main():
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name); print(f"[GREEN] {name}")

    with tempfile.TemporaryDirectory(prefix="axven_sec166_") as td:
        dd=DataDir(td)
        token=dd.load_or_create_rpc_token()
        green("secure token remains readable by daemon",dd.load_rpc_token()==token)
        green("secure token remains readable by CLI",axven_cli.resolve_rpc_auth_token(td)==token)

        # A second hardlink creates another filesystem name for the secret.
        # Both production readers must fail closed while the token has >1 link.
        alias=Path(td)/"rpc-token-alias"
        hardlink_supported=True
        try:
            os.link(dd.rpc_token_file,alias)
        except OSError:
            hardlink_supported=False
        if hardlink_supported:
            green("daemon rejects multiply-linked token file",expect_value_error(dd.load_rpc_token))
            green("CLI rejects multiply-linked token file",expect_value_error(lambda: axven_cli.resolve_rpc_auth_token(td)))
            alias.unlink()
            green("token becomes readable after hardlink removal",dd.load_rpc_token()==token)
        else:
            green("hardlink guard is present when filesystem lacks hardlinks","st_nlink" in inspect.getsource(_read_secure_rpc_token_file))

        original=dd.rpc_token_file.read_bytes()
        dd.rpc_token_file.unlink()
        dd.rpc_token_file.mkdir()
        green("daemon rejects non-regular token path",expect_value_error(dd.load_rpc_token))
        green("CLI rejects non-regular token path",expect_value_error(lambda: axven_cli.resolve_rpc_auth_token(td)))
        dd.rpc_token_file.rmdir()
        dd.rpc_token_file.write_bytes(original)
        if os.name=="posix":
            os.chmod(dd.rpc_token_file,0o600)

        symlink_target=Path(td)/"token-target"
        symlink_target.write_bytes(original)
        if os.name=="posix": os.chmod(symlink_target,0o600)
        dd.rpc_token_file.unlink()
        symlink_supported=True
        try:
            os.symlink(symlink_target,dd.rpc_token_file)
        except OSError:
            symlink_supported=False
        if symlink_supported:
            green("daemon rejects symlink token path",expect_value_error(dd.load_rpc_token))
            green("CLI rejects symlink token path",expect_value_error(lambda: axven_cli.resolve_rpc_auth_token(td)))
            dd.rpc_token_file.unlink()
        else:
            green("symlink no-follow guard is implemented","S_ISLNK" in inspect.getsource(_read_secure_rpc_token_file))
        dd.rpc_token_file.write_bytes(original)
        if os.name=="posix": os.chmod(dd.rpc_token_file,0o600)

        if os.name=="posix":
            os.chmod(dd.rpc_token_file,0o644)
            green("daemon rejects group/world-readable token",expect_value_error(dd.load_rpc_token))
            green("CLI rejects group/world-readable token",expect_value_error(lambda: axven_cli.resolve_rpc_auth_token(td)))
            os.chmod(dd.rpc_token_file,0o600)

        daemon_src=inspect.getsource(_read_secure_rpc_token_file)
        cli_src=inspect.getsource(axven_cli._read_secure_rpc_token_file)
        for label,src in (("daemon",daemon_src),("CLI",cli_src)):
            green(label+" uses lstat before open","os.lstat" in src)
            green(label+" rejects symlink metadata","stat.S_ISLNK" in src)
            green(label+" verifies opened descriptor type","os.fstat" in src and "stat.S_ISREG" in src)
            green(label+" detects path identity replacement","st_dev" in src and "st_ino" in src)
            green(label+" requests O_NOFOLLOW where supported","O_NOFOLLOW" in src)

    green("SEC-166 leaves canonical chain identity unchanged",axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    print(f"SEC-166 RPC token file integrity: {len(checks)}/{len(checks)} GREEN")

if __name__=="__main__": main()
