#!/usr/bin/env python3
"""SEC-173 cross-process datadir single-writer regression contract."""
from __future__ import annotations

import inspect
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import axven
import axven_core
from datadir import DataDir, DataDirBusyError


def _start_lock_holder(root: Path, datadir: Path, ready: Path, release: Path):
    code = r'''
import sys,time
from pathlib import Path
from datadir import DataDir
with DataDir(sys.argv[1]).runtime_lock():
    Path(sys.argv[2]).write_text("ready", encoding="utf-8")
    while not Path(sys.argv[3]).exists():
        time.sleep(0.02)
'''.strip()
    return subprocess.Popen(
        [sys.executable, "-c", code, str(datadir), str(ready), str(release)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_ready(proc, ready: Path, timeout=8.0):
    deadline=time.monotonic()+timeout
    while time.monotonic() < deadline:
        if ready.exists():
            return
        if proc.poll() is not None:
            out,err=proc.communicate()
            raise AssertionError(f"lock holder exited early: {out!r} {err!r}")
        time.sleep(0.02)
    raise AssertionError("lock holder did not become ready")


def _busy(datadir: Path):
    try:
        with DataDir(datadir).runtime_lock():
            pass
    except DataDirBusyError:
        return True
    return False


def main():
    checks=[]
    def green(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    root=Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="axven_sec173_") as td:
        datadir=Path(td)/"node"
        ready=Path(td)/"ready"
        release=Path(td)/"release"
        proc=_start_lock_holder(root,datadir,ready,release)
        try:
            _wait_ready(proc,ready)
            green(
                "second process cannot acquire an active datadir mutator lock",
                _busy(datadir),
            )
            lock_file=DataDir(datadir).runtime_lock_file
            green(
                "runtime lock is a regular persistent coordination file",
                lock_file.is_file(),
            )
            if os.name == "posix":
                mode=stat.S_IMODE(lock_file.stat().st_mode)
                green("runtime lock metadata is owner-only on POSIX", mode & 0o077 == 0)
            release.write_text("release",encoding="utf-8")
            assert proc.wait(timeout=8) == 0
        finally:
            if proc.poll() is None:
                proc.terminate(); proc.wait(timeout=8)

        with DataDir(datadir).runtime_lock():
            pass
        green("graceful holder exit releases the datadir lock", True)

        ready2=Path(td)/"ready2"
        release2=Path(td)/"release2"
        proc=_start_lock_holder(root,datadir,ready2,release2)
        try:
            _wait_ready(proc,ready2)
            assert _busy(datadir)
            proc.terminate()
            proc.wait(timeout=8)
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=8)
        with DataDir(datadir).runtime_lock():
            pass
        green("abrupt process death releases the kernel datadir lock", True)

    src=inspect.getsource(axven_core.main)
    create_pos=src.index('if args.cmd=="create-wallet":')
    create_lock=src.index("with dd.runtime_lock():",create_pos)
    create_call=src.index("dd.create_wallet",create_pos)
    green(
        "create-wallet is serialized before key material can be published",
        create_pos < create_lock < create_call,
    )

    run_pos=src.index('if args.cmd=="run":')
    run_lock=src.index("with dd.runtime_lock():",run_pos)
    load_core=src.index("core=dd.load_core(pw)",run_pos)
    final_save=src.index("_shutdown_services_and_persist(dd,core,rpc,explorer)",run_pos)
    green(
        "daemon owns the datadir lock before state load through final persistence",
        run_pos < run_lock < load_core < final_save,
    )

    green(
        "datadir serialization leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-173 datadir mutator single writer: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
