#!/usr/bin/env python3
"""Axven Explorer — local read-only block explorer for canonical devnet-2."""
from __future__ import annotations
import json, mimetypes, socket, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT=Path(__file__).resolve().parent

# Explorer v0 is intentionally loopback-only, but localhost browser/process
# traffic can still exhaust an unbounded ThreadingHTTPServer with slow or
# blocked requests.  Keep operator UI resources finite independently of RPC.
MAX_EXPLORER_WORKERS=16
EXPLORER_REQUEST_TIMEOUT=5.0
EXPLORER_REQUEST_DEADLINE=5.0


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a strict concurrent worker ceiling."""
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
    raw=json.dumps(obj,sort_keys=True,separators=(",",":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type","application/json; charset=utf-8")
    handler.send_header("Cache-Control","no-store")
    handler.send_header("Content-Length",str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)

def _handler(core):
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
                u=urlparse(self.path)
                path=u.path
                q=parse_qs(u.query)
                if path in ("/","/index.html"):
                    raw=(ROOT/"explorer_index.html").read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type","text/html; charset=utf-8")
                    self.send_header("Cache-Control","no-store")
                    self.send_header("Content-Length",str(len(raw)))
                    self.end_headers(); self.wfile.write(raw); return
                if path=="/api/summary":
                    _json(self,200,{"ok":True,"result":core.explorer_summary()}); return
                if path=="/api/blocks":
                    limit=int((q.get("limit") or ["20"])[0])
                    _json(self,200,{"ok":True,"result":core.recent_blocks(limit)}); return
                if path.startswith("/api/block/"):
                    ident=path.split("/api/block/",1)[1]
                    _json(self,200,{"ok":True,"result":core.get_block(ident)}); return
                if path.startswith("/api/tx/"):
                    txid=path.split("/api/tx/",1)[1]
                    _json(self,200,{"ok":True,"result":core.get_transaction(txid)}); return
                if path=="/api/mempool":
                    limit=int((q.get("limit") or ["100"])[0])
                    _json(self,200,{"ok":True,"result":core.mempool_view(limit)}); return
                _json(self,404,{"ok":False,"error":"not found"})
            except KeyError as e:
                _json(self,404,{"ok":False,"error":str(e)})
            except Exception as e:
                _json(self,400,{"ok":False,"error":f"{type(e).__name__}: {e}"})
    return Handler

class ExplorerServer:
    def __init__(self,core,host="127.0.0.1",port=0):
        if host not in ("127.0.0.1","localhost","::1"):
            raise ValueError("Explorer v0 may bind only to loopback")
        self.httpd=BoundedThreadingHTTPServer((host,int(port)),_handler(core))
        self.thread=None
    @property
    def address(self): return self.httpd.server_address
    def start(self):
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True)
        self.thread.start(); return self
    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()
        if self.thread:self.thread.join(2)
