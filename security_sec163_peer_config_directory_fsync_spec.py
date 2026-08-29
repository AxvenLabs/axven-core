#!/usr/bin/env python3
"""SEC-163 persisted peer-config directory durability contract."""
import inspect,tempfile
from pathlib import Path
import axven,datadir


def main():
    checks=[]
    def green(name,cond): assert cond,name; checks.append(name); print(f"[GREEN] {name}")
    src=inspect.getsource(datadir.DataDir.save_peers)
    green("peer-config rename is followed by parent directory durability barrier",src.index("os.replace(tmp_path,self.peer_file)") < src.index("_fsync_directory(self.peer_file.parent)"))
    helper=inspect.getsource(datadir._fsync_directory)
    green("peer-config directory helper is POSIX-only and closes descriptor",'os.name != "posix"' in helper and 'os.fsync(dir_fd)' in helper and 'os.close(dir_fd)' in helper)
    events=[]; oname,oopen,ofsync,oclose=datadir.os.name,datadir.os.open,datadir.os.fsync,datadir.os.close
    try:
        datadir.os.name="posix"; datadir.os.open=lambda p,f: events.append(("open",p,f)) or 93; datadir.os.fsync=lambda fd: events.append(("fsync",fd)); datadir.os.close=lambda fd: events.append(("close",fd)); datadir._fsync_directory("peer-parent")
    finally: datadir.os.name,datadir.os.open,datadir.os.fsync,datadir.os.close=oname,oopen,ofsync,oclose
    green("peer directory helper opens fsyncs and closes parent",[x[0] for x in events]==["open","fsync","close"] and events[1][1]==93 and events[2][1]==93)
    with tempfile.TemporaryDirectory() as td:
        dd=datadir.DataDir(td); peers=[("127.0.0.1",18444),("localhost",18445)]; events=[]; orepl,odir=datadir.os.replace,datadir._fsync_directory
        try:
            def repl(src,dst): events.append("replace"); return orepl(src,dst)
            datadir.os.replace=repl; datadir._fsync_directory=lambda p: events.append("dirsync"); dd.save_peers(peers)
        finally: datadir.os.replace,datadir._fsync_directory=orepl,odir
        green("peer-config save orders rename before directory fsync",events==["replace","dirsync"])
        green("peer-config durability preserves canonical round-trip",dd.load_peers()==peers)
    with tempfile.TemporaryDirectory() as td:
        dd=datadir.DataDir(td); called=[]; orepl,odir=datadir.os.replace,datadir._fsync_directory
        try:
            datadir.os.replace=lambda *_: (_ for _ in ()).throw(OSError("replace failed")); datadir._fsync_directory=lambda *_: called.append("dirsync")
            try: dd.save_peers([("127.0.0.1",18444)])
            except OSError: pass
            else: raise AssertionError("peer replace failure did not propagate")
        finally: datadir.os.replace,datadir._fsync_directory=orepl,odir
        green("failed peer-config replace never claims directory durability",called==[])
    with tempfile.TemporaryDirectory() as td:
        dd=datadir.DataDir(td); odir=datadir._fsync_directory
        try:
            datadir._fsync_directory=lambda *_: (_ for _ in ()).throw(OSError("directory fsync failed"))
            try: dd.save_peers([("127.0.0.1",18444)])
            except OSError: failed=True
            else: failed=False
        finally: datadir._fsync_directory=odir
        green("peer-config directory fsync failure propagates fail-closed",failed)
    green("SEC-163 leaves canonical identity unchanged",axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    print(f"SEC-163 peer-config directory fsync: {len(checks)}/{len(checks)} GREEN")
if __name__=='__main__': main()
