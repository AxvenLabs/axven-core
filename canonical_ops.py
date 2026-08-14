#!/usr/bin/env python3
"""Canonical devnet-2 operator helper.

This file does not modify consensus. It orchestrates the already-activated
Axven Core using persistent datadirs and loopback RPC/P2P.
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def rpc(port, method, params=None):
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    req=urllib.request.Request(f"http://127.0.0.1:{port}/",data=raw,
        headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def main():
    ap=argparse.ArgumentParser(prog="canonical-ops")
    sp=ap.add_subparsers(dest="cmd",required=True)

    s=sp.add_parser("status")
    s.add_argument("--rpc-port",type=int,default=18443)

    m=sp.add_parser("mine")
    m.add_argument("count",type=int,nargs="?",default=1)
    m.add_argument("--rpc-port",type=int,default=18443)
    m.add_argument("--scheme",default="ed25519")

    sy=sp.add_parser("sync")
    sy.add_argument("host")
    sy.add_argument("port",type=int)
    sy.add_argument("--rpc-port",type=int,default=18443)

    st=sp.add_parser("stop")
    st.add_argument("--rpc-port",type=int,default=18443)

    w=sp.add_parser("wallet")
    w.add_argument("--rpc-port",type=int,default=18443)
    w.add_argument("--scheme",default=None)

    b=sp.add_parser("balance")
    b.add_argument("--rpc-port",type=int,default=18443)
    b.add_argument("--scheme",default=None)

    u=sp.add_parser("unspent")
    u.add_argument("--rpc-port",type=int,default=18443)
    u.add_argument("--scheme",default="ed25519")

    ad=sp.add_parser("addresses")
    ad.add_argument("--rpc-port",type=int,default=18443)

    mp=sp.add_parser("mempool")
    mp.add_argument("--rpc-port",type=int,default=18443)
    mp.add_argument("--limit",type=int,default=100)

    tx=sp.add_parser("tx")
    tx.add_argument("txid")
    tx.add_argument("--rpc-port",type=int,default=18443)

    se=sp.add_parser("send")
    se.add_argument("recipient")
    se.add_argument("amount",type=int,help="amount in base units (1 AXV = 100000000)")
    se.add_argument("--fee",type=int,default=1000,help="fee in base units")
    se.add_argument("--scheme",default="ed25519")
    se.add_argument("--rpc-port",type=int,default=18443)

    pe=sp.add_parser("peers")
    pe.add_argument("--rpc-port",type=int,default=18443)

    ph=sp.add_parser("peer-health")
    ph.add_argument("--rpc-port",type=int,default=18443)

    ape=sp.add_parser("add-peer")
    ape.add_argument("host")
    ape.add_argument("port",type=int)
    ape.add_argument("--rpc-port",type=int,default=18443)

    spe=sp.add_parser("sync-peers")
    spe.add_argument("--rpc-port",type=int,default=18443)

    rpe=sp.add_parser("remove-peer")
    rpe.add_argument("host")
    rpe.add_argument("port",type=int)
    rpe.add_argument("--rpc-port",type=int,default=18443)

    ov=sp.add_parser("overview")
    ov.add_argument("--rpc-port",type=int,default=18443)

    ex=sp.add_parser("explorer")
    ex.add_argument("--rpc-port",type=int,default=18443)

    bl=sp.add_parser("blocks")
    bl.add_argument("--limit",type=int,default=20)
    bl.add_argument("--rpc-port",type=int,default=18443)

    bk=sp.add_parser("block")
    bk.add_argument("id",help="block height or hash")
    bk.add_argument("--rpc-port",type=int,default=18443)

    cc=sp.add_parser("chain-config")
    cc.add_argument("--rpc-port",type=int,default=18443)

    a=ap.parse_args()
    if a.cmd=="status":
        out=rpc(a.rpc_port,"get_status")
    elif a.cmd=="mine":
        out=rpc(a.rpc_port,"mine",{"count":a.count,"scheme":a.scheme})
    elif a.cmd=="sync":
        out=rpc(a.rpc_port,"sync_peer",{"host":a.host,"port":a.port,"batch":128})
    elif a.cmd=="stop":
        out=rpc(a.rpc_port,"stop")
    elif a.cmd=="wallet":
        params = {} if a.scheme is None else {"scheme": a.scheme}
        out=rpc(a.rpc_port,"get_wallet_status",params)
    elif a.cmd=="balance":
        params = {} if a.scheme is None else {"scheme": a.scheme}
        out=rpc(a.rpc_port,"get_balance",params)
    elif a.cmd=="unspent":
        out=rpc(a.rpc_port,"list_unspent",{"scheme":a.scheme})
    elif a.cmd=="addresses":
        out=rpc(a.rpc_port,"get_addresses")
    elif a.cmd=="mempool":
        out=rpc(a.rpc_port,"get_mempool",{"limit":a.limit})
    elif a.cmd=="tx":
        out=rpc(a.rpc_port,"get_transaction",{"txid":a.txid})
    elif a.cmd=="send":
        out=rpc(a.rpc_port,"send",{
            "input_scheme":a.scheme,
            "recipient":a.recipient,
            "amount":a.amount,
            "fee":a.fee,
        })
    elif a.cmd=="peers":
        out=rpc(a.rpc_port,"get_peers")
    elif a.cmd=="peer-health":
        out=rpc(a.rpc_port,"get_peer_health")
    elif a.cmd=="add-peer":
        out=rpc(a.rpc_port,"add_peer",{"host":a.host,"port":a.port})
    elif a.cmd=="sync-peers":
        out=rpc(a.rpc_port,"sync_peers")
    elif a.cmd=="remove-peer":
        out=rpc(a.rpc_port,"remove_peer",{"host":a.host,"port":a.port})
    elif a.cmd=="overview":
        out=rpc(a.rpc_port,"get_overview")
    elif a.cmd=="explorer":
        out=rpc(a.rpc_port,"get_explorer_summary")
    elif a.cmd=="blocks":
        out=rpc(a.rpc_port,"get_recent_blocks",{"limit":a.limit})
    elif a.cmd=="block":
        out=rpc(a.rpc_port,"get_block",{"id":a.id})
    elif a.cmd=="chain-config":
        out=rpc(a.rpc_port,"get_chain_config")
    print(json.dumps(out,indent=2,sort_keys=True))
    if not out.get("ok",False):
        raise SystemExit(2)

if __name__=="__main__":main()
