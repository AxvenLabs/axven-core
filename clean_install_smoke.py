#!/usr/bin/env python3
"""Repository/package smoke after a fresh install."""
import json, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent
c=[]
def ok(n,x): assert x,n; c.append(n)

# Source-tree invariants
import axven
ok("chain id",axven.CHAIN_ID=="axven-devnet-2")
ok("fingerprint",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
ok("genesis",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")

# Entry scripts/modules required by a fresh checkout.
for name in ["axven_core.py","axven_cli.py","axven_console.py","explorer.py","pyproject.toml"]:
    ok("fresh file "+name,(ROOT/name).is_file())

# Package metadata should be buildable without importing from a pre-existing venv.
p=subprocess.run([sys.executable,"-m","pip","wheel","--no-deps","--no-build-isolation","-w",
                  str(ROOT/"dist-smoke"),"."],cwd=ROOT,text=True,capture_output=True)
ok("wheel build",p.returncode==0)
wheels=list((ROOT/"dist-smoke").glob("axven_core-*.whl"))
ok("wheel produced",len(wheels)==1)

print(f"Clean install smoke: {len(c)}/{len(c)} GREEN")
