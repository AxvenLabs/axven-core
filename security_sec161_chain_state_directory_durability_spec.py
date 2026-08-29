#!/usr/bin/env python3
"""SEC-161 chain-state parent-directory durability regression contract."""

import inspect
import tempfile
from pathlib import Path

import axven


def main():
    checks=[]

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    with tempfile.TemporaryDirectory(prefix="axven_sec161_") as td:
        store=axven.StateStore(td)
        chain=axven.Blockchain()
        wallet=axven.Wallet()
        chain.mine(wallet.address)

        events=[]
        original_replace=axven.os.replace
        original_dirsync=axven._fsync_directory
        try:
            def tracked_replace(src,dst):
                events.append("replace")
                return original_replace(src,dst)

            def tracked_dirsync(path):
                events.append(("dirsync",Path(path)))

            axven.os.replace=tracked_replace
            axven._fsync_directory=tracked_dirsync
            store.persist(chain)
        finally:
            axven.os.replace=original_replace
            axven._fsync_directory=original_dirsync

        green(
            "chain-state replace is followed by parent-directory durability barrier",
            len(events)==2
            and events[0]=="replace"
            and events[1]==("dirsync",Path(td)),
        )
        loaded=store.load()
        green(
            "durability hardening preserves canonical chain round-trip",
            loaded.tip.hash()==chain.tip.hash() and loaded.validate(),
        )

        chain.mine(wallet.address)
        failure_events=[]
        try:
            def tracked_replace_failure_path(src,dst):
                failure_events.append("replace")
                return original_replace(src,dst)

            def fail_dirsync(path):
                failure_events.append("dirsync")
                raise OSError("simulated directory fsync failure")

            axven.os.replace=tracked_replace_failure_path
            axven._fsync_directory=fail_dirsync
            try:
                store.persist(chain)
            except OSError as exc:
                failed="directory fsync failure" in str(exc)
            else:
                failed=False
        finally:
            axven.os.replace=original_replace
            axven._fsync_directory=original_dirsync

        green(
            "directory durability failure propagates instead of reporting false success",
            failed and failure_events==["replace","dirsync"],
        )
        green(
            "post-replace durability failure leaves a parseable coherent state file",
            store.load().validate(),
        )
        leftovers=[
            p for p in Path(td).iterdir()
            if p.name.startswith(".chain.json.") and p.name.endswith(".tmp")
        ]
        green(
            "directory durability failure leaves no temporary state file",
            leftovers==[],
        )

    helper_src=inspect.getsource(axven._fsync_directory)
    green(
        "POSIX durability helper opens and fsyncs the parent directory",
        "os.open" in helper_src
        and "os.O_RDONLY" in helper_src
        and "os.fsync(fd)" in helper_src
        and "os.close(fd)" in helper_src,
    )
    green(
        "chain-state durability leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-161 chain-state directory durability: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
