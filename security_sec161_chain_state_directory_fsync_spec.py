#!/usr/bin/env python3
"""SEC-161 chain-state directory fsync durability contract."""
import inspect, tempfile
from pathlib import Path
import axven


def main():
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name); print(f"[GREEN] {name}")

    src=inspect.getsource(axven.StateStore.persist)
    green("chain rename is followed by parent directory durability barrier",
          src.index("os.replace(tmp_path, self.path)") < src.index("_fsync_directory(self.directory)"))

    helper_src=inspect.getsource(axven._fsync_directory)
    green("directory fsync is POSIX-only and closes its descriptor",
          'os.name != "posix"' in helper_src and 'os.fsync(dir_fd)' in helper_src and 'os.close(dir_fd)' in helper_src)

    events=[]
    orig_name,orig_open,orig_fsync,orig_close=axven.os.name,axven.os.open,axven.os.fsync,axven.os.close
    try:
        axven.os.name="posix"
        axven.os.open=lambda path,flags: events.append(("open",path,flags)) or 77
        axven.os.fsync=lambda fd: events.append(("fsync",fd))
        axven.os.close=lambda fd: events.append(("close",fd))
        axven._fsync_directory("parent-dir")
    finally:
        axven.os.name,axven.os.open,axven.os.fsync,axven.os.close=orig_name,orig_open,orig_fsync,orig_close
    green("directory helper opens fsyncs and closes the parent directory",
          [e[0] for e in events]==["open","fsync","close"] and events[1][1]==77 and events[2][1]==77)

    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td); chain=axven.Blockchain(); w=axven.Wallet(); chain.mine(w.address)
        events=[]
        orig_replace,orig_dirsync=axven.os.replace,axven._fsync_directory
        try:
            def tracked_replace(src,dst):
                events.append("replace"); return orig_replace(src,dst)
            def tracked_dirsync(directory): events.append("dirsync")
            axven.os.replace=tracked_replace; axven._fsync_directory=tracked_dirsync
            store.persist(chain)
        finally:
            axven.os.replace,axven._fsync_directory=orig_replace,orig_dirsync
        green("successful chain persist orders replace before directory fsync",events==["replace","dirsync"])
        green("durability hardening preserves loadable chain state",store.load().tip.hash()==chain.tip.hash() and store.load().validate())

    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td); chain=axven.Blockchain(); called=[]
        orig_replace,orig_dirsync=axven.os.replace,axven._fsync_directory
        try:
            axven.os.replace=lambda *_: (_ for _ in ()).throw(OSError("replace failed"))
            axven._fsync_directory=lambda *_: called.append("dirsync")
            try: store.persist(chain)
            except OSError: pass
            else: raise AssertionError("replace failure did not propagate")
        finally:
            axven.os.replace,axven._fsync_directory=orig_replace,orig_dirsync
        green("failed replace never claims directory durability",called==[])

    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td); chain=axven.Blockchain()
        orig_dirsync=axven._fsync_directory
        try:
            axven._fsync_directory=lambda *_: (_ for _ in ()).throw(OSError("directory fsync failed"))
            try: store.persist(chain)
            except OSError: failed=True
            else: failed=False
        finally: axven._fsync_directory=orig_dirsync
        green("directory fsync failure propagates fail-closed",failed)

    green("SEC-161 leaves canonical identity unchanged",
          axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    print(f"SEC-161 chain-state directory fsync: {len(checks)}/{len(checks)} GREEN")

if __name__=='__main__': main()
