#!/usr/bin/env python3
import json, os, subprocess, sys, tempfile, shutil
import axven, wallet
from datadir import DataDir
from core import AxvenCore
from rpc import RPCServer

def main():
    c=[]
    def ok(n,x): assert x,n; c.append(n)
    ed=axven.Wallet()
    ident=wallet.WalletIdentity(
        ed_keypair=(ed.public_key,ed.private_key),
        ml_keypair=(b"\x51"*1312,b"\x61"*2560)
    )
    pw="correct horse battery staple"

    b=wallet.export_backup(ident,pw)
    ok("backup version",b["version"]==1)
    ok("backup encrypted",b["cipher"]=="aes-256-gcm" and "ciphertext" in b)
    ok("no plaintext top-level",not any(k in b for k in ("ed_private","ml_secret","ml_public")))
    restored=wallet.restore_backup(b,pw)
    ok("restore N",restored.address_n==ident.address_n)
    ok("restore M",restored.address_m==ident.address_m)
    ok("restore H",restored.address_h==ident.address_h)

    try: wallet.restore_backup(b,"wrong"); raise AssertionError("wrong pass accepted")
    except wallet.BackupError: c.append("wrong pass rejected")
    bad=dict(b); bad["ciphertext"]=("A" if b["ciphertext"][0]!="A" else "B")+b["ciphertext"][1:]
    try: wallet.restore_backup(bad,pw); raise AssertionError("tamper accepted")
    except wallet.BackupError: c.append("tamper rejected")

    d=tempfile.mkdtemp(prefix="axven_cp7_")
    try:
        dd=DataDir(d)
        wallet.save_backup_file(ident,dd.wallet_file,pw)
        core=dd.load_core(pw)
        ok("datadir wallet restored",core.identity.address_n==ident.address_n)
        core.mine(axven.COINBASE_MATURITY+2,axven.SCHEME_ED25519)
        tip=core.chain.tip.hash(); h=core.chain.tip.height
        dd.save_chain(core.chain)
        core2=dd.load_core(pw)
        ok("datadir chain height",core2.chain.tip.height==h)
        ok("datadir chain tip",core2.chain.tip.hash()==tip)
        ok("datadir chain validates",core2.chain.validate())

        # Real CLI client against localhost RPC.
        srv=RPCServer(core2,port=0).start()
        try:
            cmd=[sys.executable,"axven_cli.py","--rpc-port",str(srv.address[1]),"status"]
            p=subprocess.run(cmd,cwd=os.path.dirname(__file__),text=True,capture_output=True,timeout=10)
            ok("cli status exit",p.returncode==0)
            out=json.loads(p.stdout)
            ok("cli status rpc",out["ok"] and out["result"]["tip_hash"]==tip)

            cmd=[sys.executable,"axven_cli.py","--rpc-port",str(srv.address[1]),
                 "balance","--scheme",axven.SCHEME_ED25519]
            p=subprocess.run(cmd,cwd=os.path.dirname(__file__),text=True,capture_output=True,timeout=10)
            out=json.loads(p.stdout)
            ok("cli balance",out["ok"] and out["result"]>0)

            cmd=[sys.executable,"axven_cli.py","--rpc-port",str(srv.address[1]),
                 "mine","1","--scheme",axven.SCHEME_ED25519]
            p=subprocess.run(cmd,cwd=os.path.dirname(__file__),text=True,capture_output=True,timeout=10)
            out=json.loads(p.stdout)
            ok("cli mine",out["ok"] and len(out["result"])==1)
        finally:srv.stop()
    finally:
        shutil.rmtree(d)

    print(f"Wallet persistence/CLI: {len(c)}/{len(c)} GREEN")

if __name__=="__main__":main()
