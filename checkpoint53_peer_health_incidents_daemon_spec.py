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


_rpc_tokens={}
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
    _rpc_tokens[rpc_port]=DataDir(datadir).load_or_create_rpc_token()
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


root=tempfile.mkdtemp(prefix="axven_checkpoint53_daemon_")

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
        "new daemon peer has no active incident",
        initial["health_incident_active"] is False,
    )

    ok(
        "new daemon peer has zero incidents",
        initial["health_incident_count"] == 0,
    )

    ok(
        "new daemon peer has no incident start timestamp",
        initial["health_incident_started_at"] is None,
    )

    ok(
        "new daemon peer has no completed incident",
        initial["last_health_incident"] is None,
    )

    offline=wait_health_state(a_rpc,"offline",deadline=8)

    ok(
        "offline transition opens health incident",
        offline["health_incident_active"] is True,
    )

    ok(
        "offline transition creates first incident",
        offline["health_incident_count"] == 1,
    )

    started_at=offline["health_incident_started_at"]

    ok(
        "offline incident exposes start timestamp",
        isinstance(started_at,str)
        and started_at.endswith("Z"),
    )

    backoff=wait_health_state(a_rpc,"backoff",deadline=8)

    ok(
        "backoff keeps incident active",
        backoff["health_incident_active"] is True,
    )

    ok(
        "backoff remains same incident",
        backoff["health_incident_count"] == 1,
    )

    ok(
        "backoff preserves incident start timestamp",
        backoff["health_incident_started_at"] == started_at,
    )

    time.sleep(.2)
    stable=peer_state(a_rpc)

    ok(
        "unchanged backoff does not create incident",
        stable["health_incident_count"] == 1
        and stable["health_incident_started_at"] == started_at,
    )

    b_proc=start_daemon(b_dir,b_rpc,b_p2p)
    wait_rpc(b_rpc)

    recovered=wait_health_state(a_rpc,"recovered",deadline=15)

    ok(
        "recovery closes active incident",
        recovered["health_incident_active"] is False,
    )

    ok(
        "recovery clears active incident timestamp",
        recovered["health_incident_started_at"] is None,
    )

    ok(
        "recovery preserves incident count",
        recovered["health_incident_count"] == 1,
    )

    incident=recovered["last_health_incident"]

    ok(
        "recovery exposes completed incident",
        isinstance(incident,dict),
    )

    ok(
        "completed incident records opening state",
        incident["from_state"] == "never_connected",
    )

    ok(
        "completed incident records last unhealthy state",
        incident["last_unhealthy_state"] == "backoff",
    )

    ok(
        "completed incident records recovery state",
        incident["recovered_to"] == "recovered",
    )

    ok(
        "completed incident preserves start timestamp",
        incident["started_at"] == started_at,
    )

    ok(
        "completed incident exposes end timestamp",
        isinstance(incident["ended_at"],str)
        and incident["ended_at"].endswith("Z"),
    )

    ok(
        "completed incident counts unhealthy transitions",
        incident["unhealthy_transitions"] == 2,
    )

    ok(
        "incident end matches recovery transition",
        incident["ended_at"]
        == recovered["last_health_transition_at"],
    )

    ok(
        "daemon history still records full lifecycle",
        [
            entry["to_state"]
            for entry in recovered["health_history"]
        ] == ["offline","backoff","recovered"],
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
    f"Checkpoint 53 daemon health incidents: "
    f"{len(checks)}/{len(checks)} GREEN"
)
