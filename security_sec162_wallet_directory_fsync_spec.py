#!/usr/bin/env python3
"""SEC-162 encrypted wallet-file directory durability contract."""
import inspect,tempfile
from pathlib import Path
import axven,wallet

def main():
    checks=[]
    def green(name,cond): assert cond,name; checks.append(name); print(f"[GREEN] {name}")
    src=inspect.getsource(wallet.save_backup_file)
    green("wallet atomic rename is followed by directory durability barrier",src.index("os.replace(tmp_path, target)") < src.index("_fsync_directory(parent)"))
    helper=inspect.getsource(wallet._fsync_directory)
    green("wallet directory helper is POSIX-only and closes descriptor",'os.name != "posix"' in helper and 'os.fsync(dir_fd)' in helper and 'os.close(dir_fd)' in helper)
    events=[]; oname,oopen,ofsync,oclose=wallet.os.name,wallet.os.open,wallet.os.fsync,wallet.os.close
    try:
        wallet.os.name="posix"; wallet.os.open=lambda p,f: events.append(("open",p,f)) or 91; wallet.os.fsync=lambda fd: events.append(("fsync",fd)); wallet.os.close=lambda fd: events.append(("close",fd)); wallet._fsync_directory("wallet-parent")
    finally: wallet.os.name,wallet.os.open,wallet.os.fsync,wallet.os.close=oname,oopen,ofsync,oclose
    green("wallet directory helper opens fsyncs and closes parent",[x[0] for x in events]==["open","fsync","close"] and events[1][1]==91 and events[2][1]==91)
    with tempfile.TemporaryDirectory() as td:
        target=Path(td)/'wallet.json'; ident=wallet.WalletIdentity(); events=[]; orepl,odir=wallet.os.replace,wallet._fsync_directory
        try:
            def repl(src,dst): events.append("replace"); return orepl(src,dst)
            wallet.os.replace=repl; wallet._fsync_directory=lambda p: events.append("dirsync"); wallet.save_backup_file(ident,target,"sec162-pass")
        finally: wallet.os.replace,wallet._fsync_directory=orepl,odir
        loaded=wallet.load_backup_file(target,"sec162-pass")
        green("wallet save orders rename before directory fsync",events==["replace","dirsync"])
        green("wallet durability hardening preserves encrypted backup round-trip",loaded.address_n==ident.address_n and loaded.address_m==ident.address_m and loaded.address_h==ident.address_h)
    with tempfile.TemporaryDirectory() as td:
        target=Path(td)/'wallet.json'; ident=wallet.WalletIdentity(); called=[]; orepl,odir=wallet.os.replace,wallet._fsync_directory
        try:
            wallet.os.replace=lambda *_: (_ for _ in ()).throw(OSError("replace failed")); wallet._fsync_directory=lambda *_: called.append("dirsync")
            try: wallet.save_backup_file(ident,target,"sec162-pass")
            except OSError: pass
            else: raise AssertionError("wallet replace failure did not propagate")
        finally: wallet.os.replace,wallet._fsync_directory=orepl,odir
        green("failed wallet replace never claims directory durability",called==[])
    with tempfile.TemporaryDirectory() as td:
        target=Path(td)/'wallet.json'; ident=wallet.WalletIdentity(); odir=wallet._fsync_directory
        try:
            wallet._fsync_directory=lambda *_: (_ for _ in ()).throw(OSError("directory fsync failed"))
            try: wallet.save_backup_file(ident,target,"sec162-pass")
            except OSError: failed=True
            else: failed=False
        finally: wallet._fsync_directory=odir
        green("wallet directory fsync failure propagates fail-closed",failed)
    green("SEC-162 leaves canonical identity unchanged",axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    print(f"SEC-162 wallet directory fsync: {len(checks)}/{len(checks)} GREEN")
if __name__=='__main__': main()
