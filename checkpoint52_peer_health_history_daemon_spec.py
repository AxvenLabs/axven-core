#!/usr/bin/env python3
"""Checkpoint 52 daemon acceptance: automatic bounded peer health history."""

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


def wait_until(fn,deadline=15,interval=.1):
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


def wait_health_state(port,state,deadline=15):
    def check():
        item=peer_state(port)
        if item["health_state"]==state:
            return item
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


root=tempfile.mkdtemp(prefix="axven_checkpoint52_daemon_")

a_proc=None
b_proc=None

try:
    a_dir=os.path.join(root,"nodeA")
    b_dir=os.path.join(root,"nodeB")

    a_rpc=free_port()
    a_p2p=free_port()

    b_rpc=free_port()
    b_p2p=free_port()

    DataDir(a_dir).save_peers([
        ("127.0.0.1",b_p2p),
    ])

    a_proc=start_daemon(a_dir,a_rpc,a_p2p)
    wait_rpc(a_rpc)

    initial=peer_state(a_rpc)

    ok(
        "new daemon peer exposes empty history",
        initial["health_history"] == [],
    )

    offline=wait_health_state(a_rpc,"offline",deadline=8)
    history=offline["health_history"]

    ok(
        "offline transition creates first history entry",
        len(history)==1,
    )

    ok(
        "offline history source is never connected",
        history[0]["from_state"]=="never_connected",
    )

    ok(
        "offline history destination is offline",
        history[0]["to_state"]=="offline",
    )

    backoff=wait_health_state(a_rpc,"backoff",deadline=8)
    history=backoff["health_history"]

    ok(
        "backoff appends second history entry",
        len(history)==2,
    )

    ok(
        "backoff history preserves order",
        history[0]["to_state"]=="offline"
        and history[1]["from_state"]=="offline"
        and history[1]["to_state"]=="backoff",
    )

    stable_history=list(history)
    time.sleep(.2)

    ok(
        "unchanged backoff does not append history",
        peer_state(a_rpc)["health_history"]==stable_history,
    )

    b_proc=start_daemon(b_dir,b_rpc,b_p2p)
    wait_rpc(b_rpc)

    recovered=wait_health_state(a_rpc,"recovered",deadline=15)
    history=recovered["health_history"]

    ok(
        "recovery appends third history entry",
        len(history)==3,
    )

    ok(
        "recovery history records backoff to recovered",
        history[-1]["from_state"]=="backoff"
        and history[-1]["to_state"]=="recovered",
    )

    ok(
        "daemon history entries expose timestamps",
        all(
            isinstance(entry["at"],str)
            and entry["at"].endswith("Z")
            for entry in history
        ),
    )

    ok(
        "daemon history schema is stable",
        all(
            set(entry)=={"from_state","to_state","at"}
            for entry in history
        ),
    )

    ok(
        "transition count matches daemon history",
        recovered["health_transition_count"]==len(history)==3,
    )

    ok(
        "both daemons remain alive",
        a_proc.poll() is None
        and b_proc.poll() is None,
    )

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
    f"Checkpoint 52 daemon health history: "
    f"{len(checks)}/{len(checks)} GREEN"
)
