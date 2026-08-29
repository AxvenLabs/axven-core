#!/usr/bin/env python3
"""SEC-134 bound Explorer HTTP workers and slow request lifetime."""

import inspect
import json
import socket
import threading
import time
import urllib.error
import urllib.request

import axven
import explorer


class BlockingCore:
    def __init__(self):
        self.lock=threading.Lock()
        self.release=threading.Event()
        self.active=0
        self.max_active=0

    def explorer_summary(self):
        with self.lock:
            self.active += 1
            self.max_active=max(self.max_active,self.active)
        try:
            self.release.wait(10.0)
            return {"height":0}
        finally:
            with self.lock:
                self.active -= 1


class HealthyCore:
    def explorer_summary(self):
        return {"height":0,"chain_id":axven.CHAIN_ID}


def wait_for(predicate,timeout=3.0):
    deadline=time.monotonic()+timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def send_summary(address,start,errors):
    start.wait()
    try:
        with urllib.request.urlopen(
            f"http://{address[0]}:{address[1]}/api/summary",
            timeout=10.0,
        ) as response:
            response.read()
    except (OSError,urllib.error.URLError) as exc:
        errors.append(exc)


def healthy_summary(address):
    with urllib.request.urlopen(
        f"http://{address[0]}:{address[1]}/api/summary",
        timeout=2.0,
    ) as response:
        data=json.loads(response.read())
        return response.status,data


def main():
    checks=[]
    def green(name,condition):
        assert condition,name
        checks.append(name)
        print("[GREEN]",name)

    green(
        "Explorer worker and receive budgets are pinned",
        explorer.MAX_EXPLORER_WORKERS == 16
        and explorer.EXPLORER_REQUEST_TIMEOUT == 5.0
        and explorer.EXPLORER_REQUEST_DEADLINE == 5.0,
    )

    # Fill every production worker slot deterministically.  Starting a large
    # client burst and hoping the scheduler observes all 16 handlers at once is
    # flaky across Python/Windows revisions; instead admit one real HTTP request
    # at a time and wait until its handler has entered the blocking core.
    core=BlockingCore()
    server=explorer.ExplorerServer(core,port=0).start()
    clients=[]
    overflow=None
    try:
        request=(
            b"GET /api/summary HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
        )
        for expected in range(1,explorer.MAX_EXPLORER_WORKERS + 1):
            client=socket.create_connection(server.address,timeout=2.0)
            client.settimeout(2.0)
            client.sendall(request)
            clients.append(client)
            if not wait_for(lambda n=expected: core.active >= n,timeout=2.0):
                raise AssertionError(
                    f"Explorer worker slot {expected} was not admitted"
                )

        with core.lock:
            active_at_cap=core.active
            peak_at_cap=core.max_active
        green(
            "Explorer concurrent request workers reach the exact configured cap",
            active_at_cap == explorer.MAX_EXPLORER_WORKERS
            and peak_at_cap == explorer.MAX_EXPLORER_WORKERS,
        )

        # The next accepted TCP socket must be rejected by process_request before
        # a request handler can enter core.explorer_summary().
        overflow=socket.create_connection(server.address,timeout=2.0)
        overflow.settimeout(2.0)
        overflow.sendall(request)
        rejected=False
        try:
            rejected=overflow.recv(1) == b""
        except (ConnectionResetError,ConnectionAbortedError,OSError):
            rejected=True
        with core.lock:
            active_after_overflow=core.active
            peak_after_overflow=core.max_active
        green(
            "Explorer concurrent request workers are strictly bounded",
            rejected
            and active_after_overflow == explorer.MAX_EXPLORER_WORKERS
            and peak_after_overflow == explorer.MAX_EXPLORER_WORKERS,
        )
        green(
            "worker saturation does not exceed semaphore capacity",
            peak_after_overflow <= explorer.MAX_EXPLORER_WORKERS,
        )
    finally:
        core.release.set()
        if overflow is not None:
            try: overflow.close()
            except OSError: pass
        for client in clients:
            try:
                while client.recv(4096):
                    pass
            except OSError:
                pass
            try: client.close()
            except OSError: pass
        server.stop()

    original_deadline=explorer.EXPLORER_REQUEST_DEADLINE
    original_timeout=explorer.EXPLORER_REQUEST_TIMEOUT
    explorer.EXPLORER_REQUEST_DEADLINE=0.30
    explorer.EXPLORER_REQUEST_TIMEOUT=2.0
    server=explorer.ExplorerServer(HealthyCore(),port=0).start()
    slow=None
    try:
        slow=socket.create_connection(server.address,timeout=1.0)
        slow.settimeout(2.0)
        started=time.monotonic()
        slow.sendall(
            b"GET /api/summary HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"X-Slow: partial"
        )
        closed=False
        try:
            while True:
                data=slow.recv(4096)
                if not data:
                    closed=True
                    break
        except OSError:
            closed=True
        elapsed=time.monotonic()-started
        green(
            "partial Explorer headers hit absolute request deadline",
            closed and 0.15 <= elapsed < 1.5,
        )
        status,data=healthy_summary(server.address)
        green(
            "Explorer listener remains healthy after slowloris eviction",
            status == 200 and data["result"]["height"] == 0,
        )
    finally:
        if slow is not None:
            try: slow.close()
            except OSError: pass
        server.stop()
        explorer.EXPLORER_REQUEST_DEADLINE=original_deadline
        explorer.EXPLORER_REQUEST_TIMEOUT=original_timeout

    try:
        explorer.ExplorerServer(HealthyCore(),host="0.0.0.0")
        loopback_only=False
    except ValueError:
        loopback_only=True
    green("Explorer remains loopback-only",loopback_only)

    handler_src=inspect.getsource(explorer._handler)
    bounded_src=inspect.getsource(explorer.BoundedThreadingHTTPServer)
    server_src=inspect.getsource(explorer.ExplorerServer)
    green(
        "absolute deadline starts before HTTP request parsing",
        "def setup(self):" in handler_src
        and "threading.Timer(" in handler_src
        and "EXPLORER_REQUEST_DEADLINE" in handler_src,
    )
    green(
        "completed GET cancels absolute receive deadline before core dispatch",
        "def do_GET(self):" in handler_src
        and "self._cancel_request_deadline()" in handler_src
        and handler_src.index("self._cancel_request_deadline()",handler_src.index("def do_GET"))
        < handler_src.index("core.explorer_summary()"),
    )
    green(
        "worker semaphore releases on every request-thread exit",
        "BoundedSemaphore(MAX_EXPLORER_WORKERS)" in bounded_src
        and "self._worker_slots.release()" in bounded_src
        and "finally:" in bounded_src,
    )
    green(
        "production Explorer uses bounded HTTP server",
        "self.httpd=BoundedThreadingHTTPServer(" in server_src
        and "self.httpd=ThreadingHTTPServer(" not in server_src,
    )
    green(
        "Explorer resource hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-134 Explorer HTTP resource bounds: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
