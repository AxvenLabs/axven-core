#!/usr/bin/env python3
"""Axven Core daemon / maintenance CLI — checkpoint 7."""
from __future__ import annotations
import argparse, getpass, json, os, signal, sys, time
from datadir import DataDir
from rpc import RPCServer
from explorer import ExplorerServer

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
        ident=dd.create_wallet(_passphrase(confirm=True))
        print(json.dumps({"N":ident.address_n,"M":ident.address_m,"H":ident.address_h},indent=2))
        return

    if args.cmd=="status":
        chain=dd.load_chain()
        print(json.dumps({"height":chain.tip.height,"tip_hash":chain.tip.hash(),
                          "chain_id":__import__("axven").CHAIN_ID},indent=2))
        return

    if args.cmd=="run":
        pw=_passphrase() if dd.has_wallet() else None
        core=dd.load_core(pw)
        p2p_addr=core.start_p2p(args.p2p_host,args.p2p_port)
        rpc=RPCServer(core,args.rpc_host,args.rpc_port).start()
        explorer=ExplorerServer(core,args.explorer_host,args.explorer_port).start()
        for raw_peer in args.peer:
            core.add_outbound_peer(raw_peer)
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
        try:
            next_sync=time.monotonic()+max(.5,args.sync_interval)
            while not stop and not core.shutdown_requested:
                time.sleep(.2)
                if core.outbound_peers and time.monotonic() >= next_sync:
                    core.sync_outbound_peers()
                    next_sync=time.monotonic()+max(.5,args.sync_interval)
        finally:
            dd.save_chain(core.chain)
            explorer.stop(); rpc.stop(); core.stop_p2p()

if __name__=="__main__": main()
