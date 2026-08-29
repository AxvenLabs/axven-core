#!/usr/bin/env python3
"""Checkpoint 47: daemon retry observability acceptance contract."""

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


_rpc_tokens={}
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

    headers={"Content-Type":"application/json"}
    token=_rpc_tokens.get(port)
    if token is not None:
        headers["Authorization"]="Bearer "+token

    req=urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=raw,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req,timeout=timeout) as r:
        return json.loads(r.read())


def wait_rpc(port, deadline=10):
    end=time.time()+deadline
    last=None

    while time.time() < end:
        try:
            result=rpc(port,"get_status")
            if result.get("ok"):
                return result
        except Exception as e:
            last=e
        time.sleep(.05)

    raise RuntimeError(f"RPC did not start: {last}")


def wait_until(fn, deadline=12, interval=.05):
    end=time.time()+deadline
    last=None

    while time.time() < end:
        try:
            value=fn()
            if value:
                return value
        except Exception as e:
            last=e
        time.sleep(interval)

    raise AssertionError(f"condition not reached; last={last}")


def peer_state(rpc_port):
    peers=rpc(rpc_port,"get_peers")["result"]
    assert len(peers)==1
    return peers[0]


def wait_failure_count(rpc_port, count, deadline=12):
    return wait_until(
        lambda: (
            state
            if (state := peer_state(rpc_port))["consecutive_failures"] >= count
            else None
        ),
        deadline=deadline,
    )


def start_daemon(datadir,rpc_port,p2p_port):
    _rpc_tokens[rpc_port]=DataDir(datadir).load_or_create_rpc_token()
    return subprocess.Popen(
        [
            sys.executable,
            "axven_core.py",
            "--datadir",str(datadir),
            "run",
            "--rpc-port",str(rpc_port),
            "--p2p-port",str(p2p_port),
            "--sync-interval","0.5",
        ],
        cwd=os.path.dirname(__file__),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_daemon(proc,rpc_port):
    if proc is None:
        return

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
        raise AssertionError(
            f"daemon exited {proc.returncode}: {err}"
        )


root=tempfile.mkdtemp(prefix="axven_checkpoint47_")
proc=None

try:
    datadir=os.path.join(root,"node")
    rpc_port=free_port()
    p2p_port=free_port()
    offline_port=free_port()

    dd=DataDir(datadir)

    # Persist one deliberately offline peer before daemon startup.
    dd.save_peers([
        ("127.0.0.1",offline_port),
    ])

    proc=start_daemon(datadir,rpc_port,p2p_port)
    wait_rpc(rpc_port)

    first=wait_failure_count(rpc_port,1,deadline=8)

    ok("retry delay exposed after first failure",
       first["retry_delay_seconds"] == 0.5)

    ok("next retry timestamp exposed",
       isinstance(first["next_retry_at"],str)
       and first["next_retry_at"].endswith("Z"))

    ok("first failure remains at base interval",
       first["retry_backoff_active"] is False)

    second=wait_failure_count(rpc_port,2,deadline=8)

    ok("second failure doubles observable retry delay",
       second["retry_delay_seconds"] == 1.0)

    ok("second failure activates observable backoff",
       second["retry_backoff_active"] is True)

    second_timestamp=second["next_retry_at"]

    time.sleep(.25)
    during=peer_state(rpc_port)

    ok("next retry timestamp stable while waiting",
       during["next_retry_at"] == second_timestamp)

    third=wait_failure_count(rpc_port,3,deadline=8)

    ok("third failure doubles observable delay again",
       third["retry_delay_seconds"] == 2.0)

    ok("retry timestamp advances after retry",
       third["next_retry_at"] != second_timestamp)

    ok("daemon remains alive with observable backoff",
       proc.poll() is None)

finally:
    try:
        if proc is not None:
            stop_daemon(proc,rpc_port)
    finally:
        shutil.rmtree(root,ignore_errors=True)


print(
    f"Checkpoint 47 daemon retry observability: "
    f"{len(checks)}/{len(checks)} GREEN"
)
