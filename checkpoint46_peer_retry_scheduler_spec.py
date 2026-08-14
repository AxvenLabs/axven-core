#!/usr/bin/env python3
"""Checkpoint 46 daemon acceptance: per-peer retry backoff."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from datadir import DataDir

checks=[]

def ok(name, condition):
    assert condition, name
    checks.append(name)
    print(f"[GREEN] {name}", flush=True)

def free_port():
    s=socket.socket()
    s.bind(("127.0.0.1",0))
    port=s.getsockname()[1]
    s.close()
    return port

def rpc(port, method, params=None, timeout=4):
    raw=json.dumps({
        "method":method,
        "params":params or {},
    }).encode()

    req=urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=raw,
        headers={"Content-Type":"application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req,timeout=timeout) as r:
        return json.loads(r.read())

def wait_rpc(port, deadline=10):
    end=time.time()+deadline
    last=None

    while time.time()<end:
        try:
            result=rpc(port,"get_status")
            if result.get("ok"):
                return result
        except Exception as e:
            last=e
        time.sleep(.05)

    raise RuntimeError(f"RPC did not start: {last}")

def wait_failure_count(rpc_port, count, deadline=8):
    end=time.time()+deadline

    while time.time()<end:
        peers=rpc(rpc_port,"get_peers")["result"]
        if len(peers)==1 and peers[0]["consecutive_failures"] >= count:
            return peers[0]
        time.sleep(.02)

    raise AssertionError(f"failure count did not reach {count}")

def stop_daemon(proc, rpc_port):
    try:
        rpc(rpc_port,"stop")
    except Exception:
        pass

    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)

    if proc.returncode != 0:
        err=proc.stderr.read() if proc.stderr else ""
        raise AssertionError(f"daemon exited {proc.returncode}: {err}")

root=tempfile.mkdtemp(prefix="axven_checkpoint46_")
proc=None

try:
    dd=DataDir(root)

    offline_p2p=free_port()

    dd.save_peers([
        ("127.0.0.1",offline_p2p),
    ])

    rpc_port=free_port()
    local_p2p=free_port()

    proc=subprocess.Popen(
        [
            sys.executable,
            "axven_core.py",
            "--datadir",root,
            "run",
            "--rpc-port",str(rpc_port),
            "--p2p-port",str(local_p2p),
            "--sync-interval","1.0",
        ],
        cwd=os.path.dirname(__file__),
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    wait_rpc(rpc_port)

    ok("daemon starts with offline persisted peer",
       proc.poll() is None)

    first=wait_failure_count(rpc_port,1)

    ok("initial peer failure recorded",
       first["consecutive_failures"] >= 1)

    second=wait_failure_count(rpc_port,2)

    ok("second failure reached",
       second["consecutive_failures"] == 2)

    second_failure_at=second["last_failure_at"]

    time.sleep(.75)

    during_backoff=rpc(rpc_port,"get_peers")["result"][0]

    ok("backoff suppresses immediate third retry",
       during_backoff["consecutive_failures"] == 2)

    ok("failure timestamp stable during backoff",
       during_backoff["last_failure_at"] == second_failure_at)

    third=wait_failure_count(rpc_port,3,deadline=3.5)

    ok("retry resumes after backoff",
       third["consecutive_failures"] == 3)

    ok("third retry updates failure timestamp",
       third["last_failure_at"] != second_failure_at)

    ok("offline peer remains configured",
       third["host"] == "127.0.0.1"
       and third["port"] == offline_p2p)

    ok("daemon remains alive throughout backoff",
       proc.poll() is None)

    print(
        f"Checkpoint 46 daemon retry scheduler: "
        f"{len(checks)}/{len(checks)} GREEN"
    )

finally:
    if proc is not None:
        try:
            stop_daemon(proc,rpc_port)
        except Exception:
            pass

    shutil.rmtree(root,ignore_errors=True)
