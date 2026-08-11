#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys

ROOT=Path(__file__).resolve().parent
s=(ROOT/"axven_core.py").read_text(encoding="utf-8")
checks=[]
def ok(n,x): assert x,n; checks.append(n)

ok("separate rpc host",'--rpc-host' in s)
ok("separate p2p host",'--p2p-host' in s)
ok("separate explorer host",'--explorer-host' in s)
ok("legacy shared host removed",'run.add_argument("--host"' not in s)
ok("rpc uses rpc host",'RPCServer(core,args.rpc_host,args.rpc_port)' in s)
ok("p2p uses p2p host",'core.start_p2p(args.p2p_host,args.p2p_port)' in s)
ok("explorer uses explorer host",'ExplorerServer(core,args.explorer_host,args.explorer_port)' in s)

cmd=(ROOT/"start-public-p2p-node.cmd").read_text(encoding="utf-8")
ok("public p2p bind",'--p2p-host 0.0.0.0' in cmd)
ok("rpc loopback",'--rpc-host 127.0.0.1' in cmd)
ok("explorer loopback",'--explorer-host 127.0.0.1' in cmd)

p=subprocess.run([sys.executable,"axven_core.py","run","--help"],cwd=ROOT,text=True,capture_output=True)
ok("cli help",p.returncode==0 and "--p2p-host" in p.stdout and "--rpc-host" in p.stdout and "--explorer-host" in p.stdout)

print(f"Checkpoint 29 bind spec: {len(checks)}/{len(checks)} GREEN")
