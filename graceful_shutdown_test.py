#!/usr/bin/env python3
import os, subprocess, sys, tempfile, socket, time, json, urllib.request, shutil
import axven, wallet
from datadir import DataDir

def free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

def rpc(port,method,params=None,token=None):
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    headers={"Content-Type":"application/json"}
    if token is not None: headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(f"http://127.0.0.1:{port}/",data=raw,
        headers=headers,method="POST")
    with urllib.request.urlopen(req,timeout=4) as r:return json.loads(r.read())

def wait(port,token):
    end=time.time()+8
    while time.time()<end:
        try:return rpc(port,"get_status",token=token)
        except Exception:time.sleep(.05)
    raise RuntimeError("daemon did not start")

def main():
    d=tempfile.mkdtemp(prefix="axven_stop_"); pw="stop-test"
    p=None
    try:
        dd=DataDir(d)
        ed=axven.Wallet()
        ident=wallet.WalletIdentity(
            ed_keypair=(ed.public_key,ed.private_key),
            ml_keypair=(b"\x11"*1312,b"\x22"*2560))
        wallet.save_backup_file(ident,dd.wallet_file,pw)
        token=dd.load_or_create_rpc_token()
        rp,pp=free_port(),free_port()
        env=os.environ.copy(); env["AXVEN_WALLET_PASSPHRASE"]=pw
        p=subprocess.Popen([sys.executable,"axven_core.py","--datadir",d,"run",
            "--rpc-port",str(rp),"--p2p-port",str(pp)],cwd=os.path.dirname(__file__),
            env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        wait(rp,token)
        assert rpc(rp,"mine",{"count":1,"scheme":axven.SCHEME_ED25519},token)["ok"]
        tip=rpc(rp,"get_status",token=token)["result"]["tip_hash"]
        out=rpc(rp,"stop",token=token)
        assert out["ok"] and out["result"]["stopping"]
        p.wait(timeout=8)
        assert p.returncode==0,(p.returncode,p.stderr.read())
        loaded=dd.load_chain()
        assert loaded.tip.hash()==tip
        assert loaded.validate()
        print("Graceful shutdown: 6/6 GREEN")
    finally:
        if p is not None and p.poll() is None:p.kill()
        shutil.rmtree(d)

if __name__=="__main__":main()
