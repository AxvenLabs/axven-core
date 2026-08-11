#!/usr/bin/env python3
"""Axven Explorer — local read-only block explorer for canonical devnet-2."""
from __future__ import annotations
import json, mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT=Path(__file__).resolve().parent

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
        def log_message(self,fmt,*args): pass

        def do_GET(self):
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
        self.httpd=ThreadingHTTPServer((host,int(port)),_handler(core))
        self.thread=None
    @property
    def address(self): return self.httpd.server_address
    def start(self):
        import threading
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True)
        self.thread.start(); return self
    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()
        if self.thread:self.thread.join(2)
