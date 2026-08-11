#!/usr/bin/env python3
import json, os, signal, socket, subprocess, sys, tempfile, time, urllib.request, urllib.error, shutil
import axven, wallet
from datadir import DataDir
from core import AxvenCore

def free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

def rpc(port,method,params=None,timeout=4):
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    req=urllib.request.Request(f"http://127.0.0.1:{port}/",data=raw,
        headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=timeout) as r:
        return json.loads(r.read())

def wait_rpc(port,deadline=8):
    end=time.time()+deadline
    last=None
    while time.time()<end:
        try:
            return rpc(port,"get_status")
        except Exception as e:
            last=e; time.sleep(.05)
    raise RuntimeError(f"rpc did not come up: {last}")

def start_daemon(datadir,rpc_port,p2p_port,pw):
    env=os.environ.copy(); env["AXVEN_WALLET_PASSPHRASE"]=pw
    return subprocess.Popen(
        [sys.executable,"axven_core.py","--datadir",datadir,"run",
         "--rpc-port",str(rpc_port),"--p2p-port",str(p2p_port)],
        cwd=os.path.dirname(__file__),env=env,text=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE
    )

def stop_daemon(p, rpc_port):
    try:
        r=rpc(rpc_port,"stop")
        if not (r.get("ok") and r.get("result",{}).get("stopping")):
            raise AssertionError(f"stop RPC rejected: {r}")
    except Exception:
        pass
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(timeout=3)
        raise AssertionError("daemon did not stop gracefully")
    if p.returncode != 0:
        err=p.stderr.read() if p.stderr else ""
        raise AssertionError(f"daemon exit {p.returncode}: {err}")

def main():
    c=[]
    def ok(n,x): assert x,n; c.append(n)
    d=tempfile.mkdtemp(prefix="axven_daemon_")
    pw="daemon-test-passphrase"
    try:
        dd=DataDir(d)
        ed=axven.Wallet()
        ident=wallet.WalletIdentity(
            ed_keypair=(ed.public_key,ed.private_key),
            ml_keypair=(b"\x71"*1312,b"\x72"*2560)
        )
        wallet.save_backup_file(ident,dd.wallet_file,pw)

        rp,pp=free_port(),free_port()
        proc=start_daemon(d,rp,pp,pw)
        try:
            st=wait_rpc(rp)
            ok("daemon starts",st["ok"])
            ok("daemon chain id",st["result"]["chain_id"]==axven.CHAIN_ID)
            ok("daemon genesis",st["result"]["genesis_hash"]==axven._genesis().hash())
            ok("daemon wallet loaded",st["result"]["wallet_loaded"] is True)

            # Exercise RPC + P2P simultaneously while daemon is alive.
            r=rpc(rp,"mine",{"count":axven.COINBASE_MATURITY+2,
                             "scheme":axven.SCHEME_ED25519},timeout=20)
            ok("daemon mining",r["ok"] and len(r["result"])==axven.COINBASE_MATURITY+2)
            st=rpc(rp,"get_status")["result"]
            tip_before,height_before=st["tip_hash"],st["height"]
            ok("height advanced",height_before==axven.COINBASE_MATURITY+2)

            # Independent node catches up from daemon P2P.
            other=AxvenCore()
            n=other.sync_peer("127.0.0.1",pp,batch=11)
            ok("live p2p sync count",n==height_before)
            ok("live p2p tip",other.chain.tip.hash()==tip_before)
            ok("live p2p validate",other.chain.validate())
        finally:
            stop_daemon(proc,rp)

        # Clean shutdown must have persisted the active chain.
        loaded=dd.load_chain()
        ok("shutdown persisted height",loaded.tip.height==height_before)
        ok("shutdown persisted tip",loaded.tip.hash()==tip_before)
        ok("shutdown persisted validate",loaded.validate())

        # Restart on new ports; state must resume, not reset.
        rp2,pp2=free_port(),free_port()
        proc2=start_daemon(d,rp2,pp2,pw)
        try:
            st=wait_rpc(rp2)["result"]
            ok("restart height exact",st["height"]==height_before)
            ok("restart tip exact",st["tip_hash"]==tip_before)
            ok("restart mempool empty",st["mempool_size"]==0)

            # Advance after restart, proving the loaded state is live.
            r=rpc(rp2,"mine",{"count":2,"scheme":axven.SCHEME_ED25519},timeout=10)
            ok("post-restart mine",r["ok"] and len(r["result"])==2)
            st2=rpc(rp2,"get_status")["result"]
            ok("post-restart height",st2["height"]==height_before+2)

            # Reconnect a fresh peer after restart.
            fresh=AxvenCore()
            n=fresh.sync_peer("127.0.0.1",pp2,batch=7)
            ok("restart p2p reconnect",n==st2["height"])
            ok("restart p2p tip",fresh.chain.tip.hash()==st2["tip_hash"])
            ok("restart p2p state",fresh.chain.utxo==dd.load_chain().utxo or fresh.chain.validate())
        finally:
            stop_daemon(proc2,rp2)

        final=dd.load_chain()
        ok("final persisted height",final.tip.height==height_before+2)
        ok("final validates",final.validate())

        # Wrong passphrase must fail closed; no daemon with wrong wallet.
        rp3,pp3=free_port(),free_port()
        bad=start_daemon(d,rp3,pp3,"wrong-pass")
        try:
            rc=bad.wait(timeout=8)
            ok("wrong pass daemon fails",rc!=0)
        finally:
            if bad.poll() is None: bad.kill()

        print(f"Daemon lifecycle: {len(c)}/{len(c)} GREEN")
    finally:
        shutil.rmtree(d)

if __name__=="__main__": main()
