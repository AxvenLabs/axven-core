#!/usr/bin/env python3
"""Checkpoint 48: peer retry recovery observability acceptance contract."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import wallet
from datadir import DataDir


checks=[]


def ok(name,condition):
    assert condition,name
    checks.append(name)
    print(f"[GREEN] {name}",flush=True)


def free_port():
    s=socket.socket()
    s.bind(("127.0.0.1",0))
    port=s.getsockname()[1]
    s.close()
    return port


def rpc(port,method,params=None,timeout=4):
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


def wait_rpc(port,deadline=10):
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


def wait_until(fn,deadline=12,interval=.1):
    end=time.time()+deadline
    last=None

    while time.time()<end:
        try:
            value=fn()
            if value:
                return value
        except Exception as e:
            last=e
        time.sleep(interval)

    raise AssertionError(f"condition not reached; last={last}")


def peer_state(port):
    result=rpc(port,"get_peers")["result"]
    assert len(result)==1,result
    return result[0]


def wait_failure_count(port,count,deadline=12):
    def check():
        state=peer_state(port)
        if state["consecutive_failures"]>=count:
            return state
        return None

    return wait_until(check,deadline=deadline)


def wait_recovered(port,deadline=15):
    def check():
        state=peer_state(port)
        if (
            state["consecutive_failures"]==0
            and state["last_error"] is None
            and state["sync_successes"]>=1
            and state["last_success_at"] is not None
        ):
            return state
        return None

    return wait_until(check,deadline=deadline)


def start_daemon(datadir,rpc_port,p2p_port):
    env=os.environ.copy()

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
        env=env,
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

    if proc.returncode!=0:
        err=proc.stderr.read() if proc.stderr else ""
        raise AssertionError(
            f"daemon exited {proc.returncode}: {err}"
        )


root=tempfile.mkdtemp(prefix="axven_checkpoint48_")

a_proc=None
b_proc=None

try:
    a_dir=os.path.join(root,"nodeA")
    b_dir=os.path.join(root,"nodeB")

    a_rpc=free_port()
    a_p2p=free_port()

    b_rpc=free_port()
    b_p2p=free_port()

    # Persist B as A's outbound peer while B is deliberately offline.
    DataDir(a_dir).save_peers([
        ("127.0.0.1",b_p2p),
    ])

    a_proc=start_daemon(a_dir,a_rpc,a_p2p)
    wait_rpc(a_rpc)

    failed=wait_failure_count(a_rpc,3,deadline=10)

    ok("offline peer reaches observable backoff",
       failed["consecutive_failures"]>=3
       and failed["retry_backoff_active"] is True)

    ok("offline peer exposes expanded retry delay",
       failed["retry_delay_seconds"]>=2.0)

    failure_timestamp=failed["last_failure_at"]

    # Bring the exact configured peer online.
    b_proc=start_daemon(b_dir,b_rpc,b_p2p)
    wait_rpc(b_rpc)

    recovered=wait_recovered(a_rpc,deadline=15)

    ok("peer automatically recovers when reachable",
       recovered["sync_successes"]>=1)

    ok("successful recovery clears last error",
       recovered["last_error"] is None)

    ok("successful recovery resets consecutive failures",
       recovered["consecutive_failures"]==0)

    ok("successful recovery records success timestamp",
       isinstance(recovered["last_success_at"],str)
       and recovered["last_success_at"].endswith("Z"))

    ok("historical failure timestamp retained",
       recovered["last_failure_at"]==failure_timestamp)

    ok("retry delay returns to base interval",
       recovered["retry_delay_seconds"]==0.5)

    ok("retry backoff becomes inactive after recovery",
       recovered["retry_backoff_active"] is False)

    ok("next retry remains observable after recovery",
       isinstance(recovered["next_retry_at"],str)
       and recovered["next_retry_at"].endswith("Z"))

    ok("both daemons remain alive after recovery",
       a_proc.poll() is None
       and b_proc.poll() is None)

finally:
    try:
        if a_proc is not None:
            stop_daemon(a_proc,a_rpc)
    finally:
        try:
            if b_proc is not None:
                stop_daemon(b_proc,b_rpc)
        finally:
            shutil.rmtree(root,ignore_errors=True)


print(
    f"Checkpoint 48 peer retry recovery: "
    f"{len(checks)}/{len(checks)} GREEN"
)
