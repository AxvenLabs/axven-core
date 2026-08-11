#!/usr/bin/env python3
import hashlib,json,subprocess,sys,os,tempfile,shutil
from pathlib import Path
import axven,doctor

def main():
    c=[]
    def ok(n,x): assert x,n; c.append(n)
    root=Path(__file__).resolve().parent

    # Identity pins/config must remain stable.
    ok("chain id",axven.CHAIN_ID=="axven-devnet-2")
    ok("fingerprint pin",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    ok("genesis pin",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")

    # Packaging files exist and parse.
    ok("pyproject exists",(root/"pyproject.toml").exists())
    ok("runbook exists",(root/"RUNBOOK.md").exists())
    m=json.loads((root/"release_manifest.json").read_text())
    ok("manifest release",m["release"]=="axven-core-v0.9.0-devnet-github-ready-checkpoint26")
    ok("activation explicitly executed",m["activation"]=="EXECUTED")

    # Manifest hashes verify exact packaged sources.
    for name,meta in m["files"].items():
        data=(root/name).read_bytes()
        ok("hash "+name,hashlib.sha256(data).hexdigest()==meta["sha256"])
        ok("size "+name,len(data)==meta["bytes"])

    # Doctor must truthfully reflect dependency state.  In this sandbox PQ
    # dependency is absent, so it MUST fail overall rather than fake success.
    d=doctor.run()
    ok("doctor python",d["checks"]["python"]["ok"])
    ok("doctor cryptography",d["checks"]["cryptography"]["ok"])
    pq=d["checks"]["dilithium_py"]["ok"]
    if pq:
        ok("doctor full pass",d["ok"])
    else:
        ok("doctor fails closed without PQ",not d["ok"])

    # CLI help is runnable without creating a wallet.
    for script in ("axven_core.py","axven_cli.py","doctor.py"):
        p=subprocess.run([sys.executable,script,"--help"] if script!="doctor.py" else [sys.executable,script],
                         cwd=root,text=True,capture_output=True)
        if script=="doctor.py":
            ok("doctor executable",p.returncode in (0,2))
        else:
            ok("help "+script,p.returncode==0)

    # Consensus activation must not have changed during packaging.
    ok("H1",axven.CHAIN_CONFIG["pq_hybrid_activation_height"]==2000)
    ok("H2",axven.CHAIN_CONFIG["pq_pure_activation_height"]==5000)
    ok("SMT",axven.CHAIN_CONFIG["smt_activation_height"]==10000)
    ok("7MiB",axven.CHAIN_CONFIG["max_block_bytes"]==7*1024*1024)

    print(f"Release packaging: {len(c)}/{len(c)} GREEN")
    print("pq_dependency_present=",pq)

if __name__=="__main__":main()
