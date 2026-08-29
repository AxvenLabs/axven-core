#!/usr/bin/env python3
"""Axven Explorer — local read-only block explorer for canonical devnet-2."""
from __future__ import annotations
import json, mimetypes, socket, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parent

# Explorer v0 is intentionally loopback-only, but localhost browser/process
# traffic can still exhaust an unbounded ThreadingHTTPServer with slow or
# blocked requests.  Keep operator UI resources finite independently of RPC.
MAX_EXPLORER_WORKERS=16
EXPLORER_REQUEST_TIMEOUT=5.0
EXPLORER_REQUEST_DEADLINE=5.0
_ALLOWED_EXPLORER_HOSTS={"127.0.0.1","localhost","::1"}
MAX_EXPLORER_QUERY_CHARS=1024


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


def _require_safe_explorer_host(headers):
    """Reject non-loopback HTTP authorities before Explorer dispatch."""
    values=headers.get_all("Host") or []
    if len(values) != 1:
        raise ValueError("invalid host header")

    authority=values[0].strip()
    if (
        not authority
        or any(ch in authority for ch in "/\\@ \t\r\n")
    ):
        raise ValueError("invalid host header")

    if authority.startswith("["):
        end=authority.find("]")
        if end <= 1:
            raise ValueError("invalid host header")
        host=authority[1:end].lower()
        suffix=authority[end + 1:]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                raise ValueError("invalid host header")
            port=int(suffix[1:])
            if not 1 <= port <= 65535:
                raise ValueError("invalid host header")
    else:
        if authority.count(":") > 1:
            raise ValueError("invalid host header")
        if ":" in authority:
            host,port_text=authority.rsplit(":",1)
            if not port_text.isdigit():
                raise ValueError("invalid host header")
            port=int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError("invalid host header")
        else:
            host=authority
        host=host.lower()

    if host.endswith("."):
        host=host[:-1]
    if host not in _ALLOWED_EXPLORER_HOSTS:
        raise ValueError("invalid host header")


def _validate_explorer_query_budget(raw_query):
    # Request targets are attacker-controlled browser/process input even on
    # loopback. Keep query work bounded before any field parsing or core call.
    if type(raw_query) is not str:
        raise ValueError("invalid Explorer query")
    if len(raw_query) > MAX_EXPLORER_QUERY_CHARS:
        raise ValueError("Explorer query too long")
    return raw_query


def _parse_explorer_limit_query(raw_query, default, maximum):
    # Explorer currently exposes one optional query field: limit. Parse its
    # wire form directly so percent-encoding, Unicode digits, signs, numeric
    # separators, duplicate fields, and custom parser aliases cannot reach
    # int() or the service layer as alternate numeric representations.
    raw_query=_validate_explorer_query_budget(raw_query)
    if not raw_query:
        return default
    prefix="limit="
    if not raw_query.startswith(prefix) or raw_query.count("=") != 1:
        raise ValueError("invalid Explorer query")
    value_text=raw_query[len(prefix):]
    if (
        not value_text
        or len(value_text) > 3
        or not value_text.isascii()
        or not value_text.isdigit()
        or (len(value_text) > 1 and value_text.startswith("0"))
    ):
        raise ValueError("invalid Explorer limit")
    value=int(value_text)
    if value < 1 or value > maximum:
        raise ValueError("invalid Explorer limit")
    return value


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
                _require_safe_explorer_host(self.headers)
                u=urlparse(self.path)
                _validate_explorer_query_budget(u.query)
                path=u.path
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
                    limit=_parse_explorer_limit_query(u.query,20,200)
                    _json(self,200,{"ok":True,"result":core.recent_blocks(limit)}); return
                if path.startswith("/api/block/"):
                    ident=path.split("/api/block/",1)[1]
                    _json(self,200,{"ok":True,"result":core.get_block(ident)}); return
                if path.startswith("/api/tx/"):
                    txid=path.split("/api/tx/",1)[1]
                    _json(self,200,{"ok":True,"result":core.get_transaction(txid)}); return
                if path=="/api/mempool":
                    limit=_parse_explorer_limit_query(u.query,100,500)
                    _json(self,200,{"ok":True,"result":core.mempool_view(limit)}); return
                _json(self,404,{"ok":False,"error":"not found"})
            except KeyError as e:
                _json(self,404,{"ok":False,"error":str(e)})
            except Exception as e:
                _json(self,400,{"ok":False,"error":f"{type(e).__name__}: {e}"})
    return Handler

def _validate_explorer_listener_endpoint(host,port):
    if type(host) is not str:
        raise ValueError("Explorer listener host must be string")
    if host not in ("127.0.0.1","localhost","::1"):
        raise ValueError("Explorer v0 may bind only to loopback")
    if type(port) is not int:
        raise ValueError("Explorer listener port must be integer")
    if port < 0 or port > 65535:
        raise ValueError("invalid Explorer listener port")
    return host,port


class ExplorerServer:
    def __init__(self,core,host="127.0.0.1",port=0):
        host,port=_validate_explorer_listener_endpoint(host,port)
        self.httpd=BoundedThreadingHTTPServer((host,port),_handler(core))
        self.thread=None
    @property
    def address(self): return self.httpd.server_address
    def start(self):
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True)
        self.thread.start(); return self
    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()
        if self.thread:self.thread.join(2)
