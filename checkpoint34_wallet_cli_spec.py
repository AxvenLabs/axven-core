#!/usr/bin/env python3
import subprocess, sys

checks=[]

def ok(name, cond):
    assert cond, name
    checks.append(name)

def run(*args):
    p=subprocess.run(
        [sys.executable, "canonical_ops.py", *args],
        text=True,
        capture_output=True
    )
    return p.returncode, p.stdout, p.stderr

rc,out,err=run("--help")
ok("help exits zero", rc == 0)
ok("wallet command listed", "wallet" in out)
ok("balance command listed", "balance" in out)
ok("unspent command listed", "unspent" in out)

rc,out,err=run("wallet","--help")
ok("wallet help", rc == 0 and "--rpc-port" in out and "--scheme" in out)

rc,out,err=run("balance","--help")
ok("balance help", rc == 0 and "--rpc-port" in out and "--scheme" in out)

rc,out,err=run("unspent","--help")
ok("unspent help", rc == 0 and "--rpc-port" in out and "--scheme" in out)

print(f"Checkpoint 34 wallet CLI spec: {len(checks)}/{len(checks)} GREEN")
