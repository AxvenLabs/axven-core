#!/usr/bin/env python3
"""SEC-158 P2P shutdown worker-quiescence contract."""

import socket
import threading
import time

import axven
import p2p


def main():
    checks=0
    entered=threading.Event()
    release=threading.Event()
    completed=threading.Event()
    original_serve=p2p.serve_connection

    def blocking_serve(sock,session,**kwargs):
        entered.set()
        if not release.wait(3.0):
            raise AssertionError("worker release timed out")
        completed.set()

    p2p.serve_connection=blocking_serve
    server=p2p.NodeServer().start()
    client=None
    stop_thread=None
    try:
        address=server.address
        client=socket.create_connection(address,timeout=2.0)
        assert entered.wait(2.0),"P2P worker never entered test handler"

        with server._lock:
            assert len(server._workers)==1
            assert len(server._clients)==1
        checks+=1
        print("[GREEN] active inbound worker is tracked before shutdown")

        stop_done=threading.Event()
        stop_errors=[]
        def stop_server():
            try:
                server.stop()
            except Exception as exc:
                stop_errors.append(exc)
            finally:
                stop_done.set()

        stop_thread=threading.Thread(target=stop_server)
        stop_thread.start()
        time.sleep(0.15)
        assert not stop_done.is_set(),(
            "NodeServer.stop returned while an admitted worker was still active"
        )
        assert not completed.is_set()
        checks+=1
        print("[GREEN] stop waits for an in-flight P2P worker")

        release.set()
        stop_thread.join(3.0)
        assert not stop_thread.is_alive(),"NodeServer.stop did not finish after worker exit"
        assert not stop_errors,stop_errors
        assert completed.is_set()
        checks+=1
        print("[GREEN] stop returns after the active worker exits")

        with server._lock:
            assert not server._workers
            assert not server._clients
            assert not server._client_hosts
        assert server._sock is None and server._thread is None
        checks+=1
        print("[GREEN] shutdown leaves no published P2P workers or clients")

        # Once shutdown wins, the old listener cannot publish a late worker.
        try:
            late=socket.create_connection(address,timeout=0.25)
        except OSError:
            late=None
        else:
            late.close()
            raise AssertionError("P2P listener accepted a connection after stop")
        with server._lock:
            assert not server._workers and not server._clients
        checks+=1
        print("[GREEN] stopped listener cannot publish a late worker")

        # Repeated stop is safe and cannot resurrect worker state.
        server.stop()
        with server._lock:
            assert not server._workers and not server._clients
        checks+=1
        print("[GREEN] repeated P2P stop remains quiescent")
    finally:
        release.set()
        if client is not None:
            try:client.close()
            except OSError:pass
        if stop_thread is not None and stop_thread.is_alive():
            stop_thread.join(3.0)
        try:server.stop()
        except Exception:pass
        p2p.serve_connection=original_serve

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks+=1
    print("[GREEN] canonical chain identity unchanged")

    assert checks==7,checks
    print("SEC-158 P2P shutdown worker quiescence: 7/7 GREEN")


if __name__=="__main__":
    main()
