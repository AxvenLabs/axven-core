#!/usr/bin/env python3
"""Axven Core daemon / maintenance CLI — checkpoint 7."""
from __future__ import annotations
import argparse, getpass, json, os, signal, sys, time
from concurrent.futures import ThreadPoolExecutor
from datadir import DataDir
from rpc import RPCServer
from explorer import ExplorerServer

# SEC-225: periodic outbound retry scheduling must not serialize network
# latency across configured peers or build an unbounded executor queue.
MAX_DAEMON_SYNC_WORKERS=16

def _schedule_peer_retry_if_configured(core, peer, delay, base_interval):
    """Atomically publish retry metadata only for a configured peer."""
    addr=core._parse_peer(peer)
    with core._peer_lock:
        if addr not in core.outbound_peers:
            return False
        core.set_peer_retry_schedule(addr,delay,base_interval)
        return True

def _reschedule_peer_after_sync(core, peer, base_interval, cap=60.0):
    """Atomically compute/publish retry state after an outbound sync."""
    addr=core._parse_peer(peer)
    with core._peer_lock:
        if addr not in core.outbound_peers:
            return None
        retry_delay=core.peer_retry_delay(addr,base_interval,cap)
        core.set_peer_retry_schedule(addr,retry_delay,base_interval)
        core.record_peer_health_transition(addr)
        return retry_delay

def _reap_completed_peer_syncs(
    core, peer_sync_futures, peer_next_sync, base_interval
):
    """Consume completed daemon syncs without republishing retry metadata."""
    completed=0
    for future,addr in list(peer_sync_futures.items()):
        if not future.done():
            continue
        # sync_outbound_peer owns normal network-error containment and atomically
        # publishes health + observable retry metadata before its Future becomes
        # done. Preserve that timestamp instead of publishing it a second time.
        future.result()
        peer_sync_futures.pop(future,None)
        with core._peer_lock:
            if addr not in core.outbound_peers:
                retry_delay=None
            else:
                retry_delay=core.peer_retry_delay_seconds.get(addr)
                # Helper-level tests or non-daemon callers may not have enabled
                # retry publication. Compute only the local scheduler delay in
                # that case; do not mutate observable retry metadata here.
                if retry_delay is None:
                    retry_delay=core.peer_retry_delay(
                        addr,base_interval,60.0
                    )
        if retry_delay is None:
            peer_next_sync.pop(addr,None)
        else:
            peer_next_sync[addr]=time.monotonic()+retry_delay
        completed+=1
    return completed

def _submit_due_peer_syncs(
    core, executor, peer_sync_futures, peer_next_sync, now
):
    """Submit only as many due peers as there are bounded worker slots."""
    slots=max(0,MAX_DAEMON_SYNC_WORKERS-len(peer_sync_futures))
    if slots == 0:
        return 0
    active=set(peer_sync_futures.values())
    submitted=0
    for addr in core.outbound_peer_addresses():
        if submitted >= slots:
            break
        if addr in active:
            continue
        if now < peer_next_sync.get(addr,now):
            continue
        future=executor.submit(core.sync_outbound_peer,addr)
        peer_sync_futures[future]=addr
        active.add(addr)
        submitted+=1
    return submitted

def _shutdown_services_and_persist(dd,core,rpc,explorer):
    """Quiesce every runtime service before writing the final chain snapshot."""
    # RPC and P2P can mutate chain state.  SEC-159 and SEC-158 make their
    # stop() calls quiescence barriers, so final persistence must happen only
    # after both have returned.  Explorer is read-only but is also stopped
    # before the final snapshot to leave no live service at persistence time.
    rpc.stop()
    core.stop_p2p()
    explorer.stop()
    dd.save_chain(core.chain)


def _passphrase(confirm=False):
    env=os.environ.get("AXVEN_WALLET_PASSPHRASE")
    if env:return env
    first=getpass.getpass("Wallet passphrase: ")
    if confirm:
        second=getpass.getpass("Repeat passphrase: ")
        if first!=second: raise SystemExit("passphrases do not match")
    return first

def main():
    ap=argparse.ArgumentParser(prog="axven-core")
    ap.add_argument("--datadir",default=os.environ.get("AXVEN_DATADIR","./axven-data"))
    sp=ap.add_subparsers(dest="cmd",required=True)
    sp.add_parser("create-wallet")
    sp.add_parser("status")
    run=sp.add_parser("run")
    run.add_argument("--rpc-port",type=int,default=18443)
    run.add_argument("--p2p-port",type=int,default=18444)
    run.add_argument("--explorer-port",type=int,default=18445)
    run.add_argument("--rpc-host",default="127.0.0.1")
    run.add_argument("--p2p-host",default="127.0.0.1")
    run.add_argument("--explorer-host",default="127.0.0.1")
    run.add_argument("--peer",action="append",default=[],
                     help="Outbound peer as host:port; may be repeated")
    run.add_argument("--sync-interval",type=float,default=5.0,
                     help="Seconds between outbound peer sync attempts")
    args=ap.parse_args()
    dd=DataDir(args.datadir)

    if args.cmd=="create-wallet":
        with dd.runtime_lock():
            ident=dd.create_wallet(_passphrase(confirm=True))
            print(json.dumps({"N":ident.address_n,"M":ident.address_m,"H":ident.address_h},indent=2))
        return

    if args.cmd=="status":
        chain=dd.load_chain()
        print(json.dumps({"height":chain.tip.height,"tip_hash":chain.tip.hash(),
                          "chain_id":__import__("axven").CHAIN_ID},indent=2))
        return

    if args.cmd=="run":
        with dd.runtime_lock():
            pw=_passphrase() if dd.has_wallet() else None
            core=dd.load_core(pw)
            rpc_token=dd.load_or_create_rpc_token()
            if rpc_token is None:
                raise RuntimeError("RPC authentication token unavailable")
            p2p_addr=core.start_p2p(args.p2p_host,args.p2p_port)
            rpc=RPCServer(
                core,args.rpc_host,args.rpc_port,auth_token=rpc_token
            ).start()
            explorer=ExplorerServer(core,args.explorer_host,args.explorer_port).start()
            for raw_peer in args.peer:
                core.add_outbound_peer(raw_peer)
            base_sync_interval=max(.5,args.sync_interval)
            core.configure_peer_retry_publication(base_sync_interval,60.0)
            initial_sync=core.sync_outbound_peers()

            print(json.dumps({"rpc":{"host":rpc.address[0],"port":rpc.address[1]},
                              "p2p":{"host":p2p_addr[0],"port":p2p_addr[1]},
                              "explorer":{"host":explorer.address[0],"port":explorer.address[1]},
                              "height":core.chain.tip.height,
                              "outbound_peers":core.outbound_peer_status(),
                              "initial_sync":initial_sync},indent=2),flush=True)
            stop=False
            def halt(*_):
                nonlocal stop; stop=True
            signal.signal(signal.SIGINT,halt)
            signal.signal(signal.SIGTERM,halt)
            peer_sync_executor=ThreadPoolExecutor(
                max_workers=MAX_DAEMON_SYNC_WORKERS,
                thread_name_prefix="axven-peer-sync",
            )
            peer_sync_futures={}
            try:
                peer_next_sync={
                    addr:time.monotonic()+base_sync_interval
                    for addr in core.outbound_peer_addresses()
                }
                for addr in core.outbound_peer_addresses():
                    if not _schedule_peer_retry_if_configured(
                        core,
                        addr,
                        base_sync_interval,
                        base_sync_interval,
                    ):
                        peer_next_sync.pop(addr,None)

                while not stop and not core.shutdown_requested:
                    time.sleep(.2)
                    now=time.monotonic()
                    configured=set(core.outbound_peer_addresses())

                    # Drop scheduler state for peers removed at runtime.
                    for addr in list(peer_next_sync):
                        if addr not in configured:
                            peer_next_sync.pop(addr,None)

                    # Runtime-added peers start on the normal base interval.
                    for addr in configured:
                        if addr not in peer_next_sync:
                            if _schedule_peer_retry_if_configured(
                                core,
                                addr,
                                base_sync_interval,
                                base_sync_interval,
                            ):
                                peer_next_sync[addr]=now+base_sync_interval

                    # Reap only completed work, then fill at most the remaining
                    # bounded worker slots. Slow peers therefore cannot serialize
                    # healthy peers and no unbounded Future queue can accumulate.
                    _reap_completed_peer_syncs(
                        core,
                        peer_sync_futures,
                        peer_next_sync,
                        base_sync_interval,
                    )
                    _submit_due_peer_syncs(
                        core,
                        peer_sync_executor,
                        peer_sync_futures,
                        peer_next_sync,
                        now,
                    )
            finally:
                # Outbound sync may mutate chain state. Quiesce all retry workers
                # before service shutdown and the final persisted chain snapshot.
                peer_sync_executor.shutdown(wait=True, cancel_futures=False)
                _shutdown_services_and_persist(dd,core,rpc,explorer)

if __name__=="__main__": main()
