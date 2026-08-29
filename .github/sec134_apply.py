#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

EXPLORER = Path("explorer.py")
MANIFEST = Path("release_manifest.json")
SPEC_PATH = Path("security_sec134_explorer_http_resource_bounds_spec.py")
WORKFLOW = Path(".github/workflows/sec134-apply.yml")
SELF = Path(".github/sec134_apply.py")

text = EXPLORER.read_text(encoding="utf-8")

old_imports = '''import json, mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
'''
new_imports = '''import json, mimetypes, socket, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
'''
if text.count(old_imports) != 1:
    raise SystemExit("SEC-134 import anchor mismatch")
text = text.replace(old_imports, new_imports, 1)

old_root = '''ROOT=Path(__file__).resolve().parent

def _json(handler,status,obj):
'''
new_root = '''ROOT=Path(__file__).resolve().parent

# Explorer v0 is intentionally loopback-only, but localhost browser/process
# traffic can still exhaust an unbounded ThreadingHTTPServer with slow or
# blocked requests.  Keep operator UI resources finite independently of RPC.
MAX_EXPLORER_WORKERS=16
EXPLORER_REQUEST_TIMEOUT=5.0
EXPLORER_REQUEST_DEADLINE=5.0


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    \"\"\"ThreadingHTTPServer with a strict concurrent worker ceiling.\"\"\"
    def __init__(self,*args,**kwargs):
        self._worker_slots=threading.BoundedSemaphore(MAX_EXPLORER_WORKERS)
        super().__init__(*args,**kwargs)

    def process_request(self,request,client_address):
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self,request,client_address):
        try:
            super().process_request_thread(request,client_address)
        finally:
            self._worker_slots.release()


def _json(handler,status,obj):
'''
if text.count(old_root) != 1:
    raise SystemExit("SEC-134 root anchor mismatch")
text = text.replace(old_root, new_root, 1)

old_handler = '''def _handler(core):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,fmt,*args): pass

        def do_GET(self):
            try:
'''
new_handler = '''def _handler(core):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(EXPLORER_REQUEST_TIMEOUT)
            self._request_deadline_timer=threading.Timer(
                EXPLORER_REQUEST_DEADLINE,
                self._expire_request,
            )
            self._request_deadline_timer.daemon=True
            self._request_deadline_timer.start()

        def _expire_request(self):
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def _cancel_request_deadline(self):
            timer=getattr(self,"_request_deadline_timer",None)
            if timer is not None:
                timer.cancel()
                self._request_deadline_timer=None

        def finish(self):
            self._cancel_request_deadline()
            try:
                super().finish()
            except OSError:
                pass

        def log_message(self,fmt,*args): pass

        def do_GET(self):
            # BaseHTTPRequestHandler has already received and parsed the
            # request line + headers before dispatching here.  The absolute
            # deadline therefore bounds slowloris receipt without timing out
            # legitimate local core reads once a complete request exists.
            self._cancel_request_deadline()
            self.connection.settimeout(EXPLORER_REQUEST_TIMEOUT)
            try:
'''
if text.count(old_handler) != 1:
    raise SystemExit("SEC-134 handler anchor mismatch")
text = text.replace(old_handler, new_handler, 1)

old_server = '''        self.httpd=ThreadingHTTPServer((host,int(port)),_handler(core))
        self.thread=None
'''
new_server = '''        self.httpd=BoundedThreadingHTTPServer((host,int(port)),_handler(core))
        self.thread=None
'''
if text.count(old_server) != 1:
    raise SystemExit("SEC-134 server anchor mismatch")
text = text.replace(old_server, new_server, 1)

old_start = '''    def start(self):
        import threading
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True)
'''
new_start = '''    def start(self):
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True)
'''
if text.count(old_start) != 1:
    raise SystemExit("SEC-134 start anchor mismatch")
text = text.replace(old_start, new_start, 1)
EXPLORER.write_text(text, encoding="utf-8", newline="\n")

SPEC = r'''#!/usr/bin/env python3
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

    core=BlockingCore()
    server=explorer.ExplorerServer(core,port=0).start()
    start=threading.Event()
    errors=[]
    clients=[
        threading.Thread(
            target=send_summary,
            args=(server.address,start,errors),
            daemon=True,
        )
        for _ in range(explorer.MAX_EXPLORER_WORKERS + 12)
    ]
    try:
        for client in clients:
            client.start()
        start.set()
        reached=wait_for(
            lambda: core.max_active >= explorer.MAX_EXPLORER_WORKERS,
            timeout=5.0,
        )
        with core.lock:
            peak=core.max_active
        green(
            "Explorer concurrent request workers are strictly bounded",
            reached and peak == explorer.MAX_EXPLORER_WORKERS,
        )
        green(
            "worker saturation does not exceed semaphore capacity",
            peak <= explorer.MAX_EXPLORER_WORKERS,
        )
    finally:
        core.release.set()
        for client in clients:
            client.join(2.0)
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
        "BoundedThreadingHTTPServer" in server_src
        and "ThreadingHTTPServer((host" not in server_src,
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
'''
SPEC_PATH.write_text(SPEC, encoding="utf-8", newline="\n")

if WORKFLOW.exists():
    WORKFLOW.unlink()
if SELF.exists():
    SELF.unlink()

manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (EXPLORER,SPEC_PATH):
    data=path.read_bytes()
    manifest["files"][path.as_posix()]={
        "bytes":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest,indent=2,sort_keys=True)+"\n",
    encoding="utf-8",
    newline="\n",
)
print("SEC-134 Explorer patch, spec, and manifest staged")
