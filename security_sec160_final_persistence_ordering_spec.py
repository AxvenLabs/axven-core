#!/usr/bin/env python3
"""SEC-160 final persistence ordering regression contract."""

import inspect

import axven
import axven_core


class FakeCore:
    def __init__(self,events,fail=False):
        self.events=events
        self.fail=fail
        self.chain=object()
        self.p2p_quiescent=False

    def stop_p2p(self):
        self.events.append("p2p.stop")
        if self.fail:
            raise RuntimeError("p2p quiescence failed")
        self.p2p_quiescent=True


class FakeRPC:
    def __init__(self,events,fail=False):
        self.events=events
        self.fail=fail
        self.quiescent=False

    def stop(self):
        self.events.append("rpc.stop")
        if self.fail:
            raise RuntimeError("rpc quiescence failed")
        self.quiescent=True


class FakeExplorer:
    def __init__(self,events):
        self.events=events
        self.stopped=False

    def stop(self):
        self.events.append("explorer.stop")
        self.stopped=True


class FakeDataDir:
    def __init__(self,events,rpc,core,explorer):
        self.events=events
        self.rpc=rpc
        self.core=core
        self.explorer=explorer
        self.saved=None

    def save_chain(self,chain):
        assert self.rpc.quiescent,"final save ran before RPC quiescence"
        assert self.core.p2p_quiescent,"final save ran before P2P quiescence"
        assert self.explorer.stopped,"final save ran before Explorer stop"
        self.events.append("save")
        self.saved=chain


def expect_failure(fn):
    try:
        fn()
    except RuntimeError:
        return True
    return False


def main():
    checks=[]

    def green(name,condition):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    events=[]
    rpc=FakeRPC(events)
    core=FakeCore(events)
    explorer=FakeExplorer(events)
    dd=FakeDataDir(events,rpc,core,explorer)
    axven_core._shutdown_services_and_persist(dd,core,rpc,explorer)
    green(
        "final persistence follows RPC P2P and Explorer quiescence",
        events==["rpc.stop","p2p.stop","explorer.stop","save"],
    )
    green(
        "healthy final save persists the exact active chain object",
        dd.saved is core.chain,
    )

    events=[]
    rpc=FakeRPC(events,fail=True)
    core=FakeCore(events)
    explorer=FakeExplorer(events)
    dd=FakeDataDir(events,rpc,core,explorer)
    green(
        "RPC quiescence failure aborts final persistence",
        expect_failure(
            lambda: axven_core._shutdown_services_and_persist(
                dd,core,rpc,explorer
            )
        )
        and "save" not in events,
    )

    events=[]
    rpc=FakeRPC(events)
    core=FakeCore(events,fail=True)
    explorer=FakeExplorer(events)
    dd=FakeDataDir(events,rpc,core,explorer)
    green(
        "P2P quiescence failure aborts final persistence",
        expect_failure(
            lambda: axven_core._shutdown_services_and_persist(
                dd,core,rpc,explorer
            )
        )
        and events==["rpc.stop","p2p.stop"]
        and "save" not in events,
    )

    helper_src=inspect.getsource(axven_core._shutdown_services_and_persist)
    green(
        "production helper pins mutator shutdown before final save",
        helper_src.index("rpc.stop()")
        < helper_src.index("core.stop_p2p()")
        < helper_src.index("explorer.stop()")
        < helper_src.index("dd.save_chain(core.chain)"),
    )
    main_src=inspect.getsource(axven_core.main)
    green(
        "daemon finally path delegates to quiescent persistence helper",
        "_shutdown_services_and_persist(dd,core,rpc,explorer)" in main_src
        and "dd.save_chain(core.chain)\n            explorer.stop()" not in main_src,
    )
    green(
        "final persistence ordering leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-160 final persistence ordering: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
