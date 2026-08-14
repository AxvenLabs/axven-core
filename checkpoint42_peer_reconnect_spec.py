#!/usr/bin/env python3
"""Checkpoint 42: persistent peer reconnect and recovery rehearsal."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import axven
import wallet
from datadir import DataDir


checks = []


def ok(name, condition):
    assert condition, name
    checks.append(name)
    print(f"[GREEN] {name}", flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def rpc(port, method, params=None, timeout=4):
    raw = json.dumps({
        "method": method,
        "params": params or {},
    }).encode()

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=raw,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def wait_rpc(port, deadline=10):
    end = time.time() + deadline
    last = None

    while time.time() < end:
        try:
            result = rpc(port, "get_status")
            if result.get("ok"):
                return result
        except Exception as e:
            last = e
        time.sleep(0.05)

    raise RuntimeError(f"RPC did not start: {last}")


def wait_until(fn, deadline=12, interval=0.1):
    end = time.time() + deadline
    last = None

    while time.time() < end:
        try:
            value = fn()
            if value:
                return value
        except Exception as e:
            last = e
        time.sleep(interval)

    raise AssertionError(f"condition not reached; last={last}")


def start_daemon(datadir, rpc_port, p2p_port):
    env = os.environ.copy()

    return subprocess.Popen(
        [
            sys.executable,
            "axven_core.py",
            "--datadir", str(datadir),
            "run",
            "--rpc-port", str(rpc_port),
            "--p2p-port", str(p2p_port),
            "--sync-interval", "0.5",
        ],
        cwd=os.path.dirname(__file__),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_daemon(proc, rpc_port):
    if proc is None:
        return

    try:
        rpc(rpc_port, "stop")
    except Exception:
        pass

    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)

    if proc.returncode != 0:
        err = proc.stderr.read() if proc.stderr else ""
        raise AssertionError(
            f"daemon exited {proc.returncode}: {err}"
        )


root = tempfile.mkdtemp(prefix="axven_checkpoint42_")

a_proc = None
b_proc = None

try:
    a_dir = DataDir(os.path.join(root, "nodeA"))
    b_dir = DataDir(os.path.join(root, "nodeB"))

    # B gets a heavier chain before either daemon starts.
    b = b_dir.load_core()
    b.identity = wallet.WalletIdentity()
    b.mine(
        axven.COINBASE_MATURITY + 3,
        axven.SCHEME_ED25519,
    )
    b_dir.save_chain(b.chain)

    b_height = b.chain.tip.height
    b_tip = b.chain.tip.hash()

    ok("B prepared with heavier chain",
       b_height == axven.COINBASE_MATURITY + 3)

    # Reserve B's eventual P2P endpoint.
    b_rpc = free_port()
    b_p2p = free_port()

    # A persists B before B is online.
    a_dir.save_peers([
        ("127.0.0.1", b_p2p),
    ])

    ok("A persisted offline peer",
       a_dir.load_peers() == [("127.0.0.1", b_p2p)])

    # Start A while B is still OFFLINE.
    a_rpc = free_port()
    a_p2p = free_port()

    a_proc = start_daemon(a_dir.path, a_rpc, a_p2p)

    a_status = wait_rpc(a_rpc)["result"]

    ok("A starts while peer offline",
       a_status["chain_id"] == axven.CHAIN_ID)

    ok("A remains at genesis initially",
       a_status["height"] == 0)

    # Initial sync should fail, but daemon must remain healthy.
    def offline_error_visible():
        peers = rpc(a_rpc, "get_peers")["result"]
        return (
            len(peers) == 1
            and peers[0]["port"] == b_p2p
            and peers[0]["last_error"] is not None
        )

    wait_until(offline_error_visible)

    ok("offline peer error observable", True)

    ok("A daemon survives failed sync",
       a_proc.poll() is None)

    # Now B comes online later.
    b_proc = start_daemon(b_dir.path, b_rpc, b_p2p)

    b_live = wait_rpc(b_rpc)["result"]

    ok("B starts later",
       b_live["height"] == b_height)

    # A's retry loop must discover B without manual sync.
    def converged():
        st = rpc(a_rpc, "get_status")["result"]
        return (
            st["height"] == b_height
            and st["tip_hash"] == b_tip
        )

    wait_until(converged, deadline=15)

    ok("A automatically catches up",
       True)

    peer_state = rpc(a_rpc, "get_peers")["result"]

    ok("peer remains configured",
       len(peer_state) == 1
       and peer_state[0]["port"] == b_p2p)

    ok("peer error clears after recovery",
       peer_state[0]["last_error"] is None)

    # Restart A: persisted peer must still be present.
    stop_daemon(a_proc, a_rpc)
    a_proc = None

    a_rpc2 = free_port()
    a_p2p2 = free_port()

    a_proc = start_daemon(a_dir.path, a_rpc2, a_p2p2)

    restarted = wait_rpc(a_rpc2)["result"]

    ok("A restart preserves synchronized tip",
       restarted["height"] == b_height
       and restarted["tip_hash"] == b_tip)

    restarted_peers = rpc(a_rpc2, "get_peers")["result"]

    ok("persisted peer survives daemon restart",
       len(restarted_peers) == 1
       and restarted_peers[0]["host"] == "127.0.0.1"
       and restarted_peers[0]["port"] == b_p2p)

    wait_until(
        lambda: rpc(a_rpc2, "get_peers")["result"][0]["last_error"] is None,
        deadline=8,
    )

    ok("restart reconnect is healthy",
       True)

    print(
        f"Checkpoint 42 peer reconnect/recovery: "
        f"{len(checks)}/{len(checks)} GREEN"
    )

finally:
    if a_proc is not None:
        try:
            stop_daemon(a_proc, a_rpc2 if "a_rpc2" in locals() else a_rpc)
        except Exception:
            pass

    if b_proc is not None:
        try:
            stop_daemon(b_proc, b_rpc)
        except Exception:
            pass

    shutil.rmtree(root, ignore_errors=True)
