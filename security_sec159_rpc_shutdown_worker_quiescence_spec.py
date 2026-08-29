#!/usr/bin/env python3
"""SEC-159 RPC shutdown worker-quiescence regression contract."""

import json
import threading
import time
import urllib.request

import axven
import rpc


class BlockingCore:
    def __init__(self):
        self.entered=threading.Event()
        self.release=threading.Event()
        self.completed=threading.Event()
        self.completed_at=None

    def status(self):
        self.entered.set()
        if not self.release.wait(2.0):
            raise AssertionError("blocked RPC handler release timed out")
        self.completed_at=time.monotonic()
        self.completed.set()
        return {"height":0,"tip_hash":"0"*64}


def rpc_status(address):
    raw=json.dumps({"method":"get_status","params":{}}).encode()
    req=urllib.request.Request(
        f"http://{address[0]}:{address[1]}/",
        data=raw,
        headers={"Content-Type":"application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req,timeout=3.0) as response:
        return json.loads(response.read())


def main():
    checks=[]

    def green(name, condition):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    green(
        "RPC request workers are non-daemon and joinable",
        rpc.BoundedThreadingHTTPServer.daemon_threads is False,
    )
    green(
        "RPC server close waits for tracked request workers",
        rpc.BoundedThreadingHTTPServer.block_on_close is True,
    )

    core=BlockingCore()
    server=rpc.RPCServer(core,"127.0.0.1",0).start()
    request_result=[]
    request_errors=[]
    stop_errors=[]
    stop_done=threading.Event()
    stop_returned_at=[]

    def request_worker():
        try:
            request_result.append(rpc_status(server.address))
        except Exception as exc:
            request_errors.append(exc)

    def stop_worker():
        try:
            server.stop()
            stop_returned_at.append(time.monotonic())
        except Exception as exc:
            stop_errors.append(exc)
        finally:
            stop_done.set()

    request_thread=threading.Thread(target=request_worker)
    stop_thread=None
    request_thread.start()
    try:
        green(
            "RPC handler entered before shutdown",
            core.entered.wait(1.0),
        )

        stop_thread=threading.Thread(target=stop_worker)
        stop_thread.start()
        time.sleep(0.15)
        green(
            "RPC stop waits while an admitted handler is still running",
            not stop_done.is_set(),
        )

        core.release.set()
        request_thread.join(2.0)
        stop_thread.join(2.0)
        green(
            "RPC request and shutdown both quiesce",
            not request_thread.is_alive()
            and not stop_thread.is_alive()
            and not request_errors
            and not stop_errors,
        )
        green(
            "in-flight healthy RPC response completes before shutdown returns",
            len(request_result)==1
            and request_result[0].get("ok") is True
            and request_result[0].get("result",{}).get("height")==0
            and core.completed.is_set()
            and len(stop_returned_at)==1
            and stop_returned_at[0] >= core.completed_at,
        )
        green(
            "RPC listener thread is stopped after worker quiescence",
            server.thread is not None and not server.thread.is_alive(),
        )
        green(
            "ThreadingMixIn worker registry is drained on server close",
            not list(getattr(server.httpd,"_threads",())),
        )
    finally:
        core.release.set()
        request_thread.join(2.0)
        if stop_thread is not None:
            stop_thread.join(2.0)
        if not stop_done.is_set():
            server.stop()

    green(
        "RPC shutdown hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-159 RPC shutdown worker quiescence: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
