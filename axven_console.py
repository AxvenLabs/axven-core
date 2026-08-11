#!/usr/bin/env python3
"""Interactive operator/wallet console for a running Axven Core node."""
from __future__ import annotations
import argparse, json, shlex
from axven_cli import call

HELP="""
Commands:
  overview                     Node + wallet summary
  status                       Node/network status
  addresses                    N/M/H receive addresses
  balance [scheme]             All balances or one of: ed25519, ml-dsa-44, hybrid
  utxos <scheme>               Spendable UTXOs
  mine [count] [scheme]        Mine blocks
  send <scheme> <addr> <amount> <fee>
  sync <host> <p2p-port>       Synchronize from peer
  help                         Show this help
  quit / exit                  Leave console (node keeps running)
  stop                         Gracefully stop node and leave console

Amounts are raw Axven consensus units in this checkpoint.
""".strip()

def request(port,method,params=None):
    out=call("127.0.0.1",port,method,params)
    if not out.get("ok"):
        print("ERROR:",out.get("error","unknown error"))
        return None
    return out["result"]

def pretty(x):
    print(json.dumps(x,indent=2,sort_keys=True))

def main():
    ap=argparse.ArgumentParser(prog="axven-console")
    ap.add_argument("--rpc-port",type=int,default=18443)
    a=ap.parse_args()
    print("Axven Core Console — canonical axven-devnet-2")
    print("Type 'help' for commands.")
    while True:
        try: line=input("axven> ").strip()
        except (EOFError,KeyboardInterrupt):
            print(); return
        if not line: continue
        try: parts=shlex.split(line)
        except ValueError as e:
            print("ERROR:",e); continue
        cmd=parts[0].lower()
        try:
            if cmd in ("quit","exit"): return
            if cmd=="help": print(HELP); continue
            if cmd=="overview": pretty(request(a.rpc_port,"get_overview")); continue
            if cmd=="status": pretty(request(a.rpc_port,"get_status")); continue
            if cmd=="addresses": pretty(request(a.rpc_port,"get_addresses")); continue
            if cmd=="balance":
                pretty(request(a.rpc_port,"get_balance",{"scheme":parts[1] if len(parts)>1 else None})); continue
            if cmd=="utxos":
                if len(parts)!=2: raise ValueError("usage: utxos <scheme>")
                pretty(request(a.rpc_port,"list_unspent",{"scheme":parts[1]})); continue
            if cmd=="mine":
                count=int(parts[1]) if len(parts)>1 else 1
                scheme=parts[2] if len(parts)>2 else None
                pretty(request(a.rpc_port,"mine",{"count":count,"scheme":scheme})); continue
            if cmd=="send":
                if len(parts)!=5: raise ValueError("usage: send <scheme> <address> <amount> <fee>")
                pretty(request(a.rpc_port,"send",{"input_scheme":parts[1],"recipient":parts[2],
                    "amount":int(parts[3]),"fee":int(parts[4])})); continue
            if cmd=="sync":
                if len(parts)!=3: raise ValueError("usage: sync <host> <p2p-port>")
                pretty(request(a.rpc_port,"sync_peer",{"host":parts[1],"port":int(parts[2]),"batch":128})); continue
            if cmd=="stop":
                pretty(request(a.rpc_port,"stop")); return
            print("Unknown command. Type 'help'.")
        except (ValueError,IndexError) as e:
            print("ERROR:",e)

if __name__=="__main__":main()
