#!/usr/bin/env python3
"""Local JSON-RPC interface for Axven Core.

Default binding is loopback only.  This is intentionally not an Internet-facing
API; public authentication/TLS belongs to a later hardening milestone.
"""
from __future__ import annotations
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class RPCError(ValueError): pass


class RPCDispatcher:
    def __init__(self, core):
        self.core = core

    def call(self, method, params=None):
        p = params or {}
        if method == "get_status": return self.core.status()
        if method == "get_overview": return self.core.overview()
        if method == "get_explorer_summary": return self.core.explorer_summary()
        if method == "get_recent_blocks": return self.core.recent_blocks(p.get("limit",20))
        if method == "get_block": return self.core.get_block(p["id"])
        if method == "get_transaction": return self.core.get_transaction(p["txid"])
        if method == "get_mempool": return self.core.mempool_view(p.get("limit",100))
        if method == "get_chain_config": return self.core.chain_config()
        if method == "get_addresses": return self.core.addresses()
        if method == "get_balance": return self.core.balance(p.get("scheme"))
        if method == "get_wallet_status": return self.core.wallet_status(p.get("scheme"))
        if method == "list_unspent": return self.core.list_unspent(p["scheme"])
        if method == "get_peers": return self.core.outbound_peer_status()
        if method == "add_peer":
            host, port = self.core.add_outbound_peer((p["host"], int(p["port"])))
            return {"host": host, "port": port}
        if method == "sync_peers":
            return self.core.sync_outbound_peers()
        if method == "mine": return self.core.mine(int(p.get("count", 1)), p.get("scheme"))
        if method == "send":
            return self.core.send(p["input_scheme"], p["recipient"],
                                  int(p["amount"]), int(p["fee"]))
        if method == "start_p2p":
            h, port = self.core.start_p2p(p.get("host", "127.0.0.1"), int(p.get("port", 0)))
            return {"host": h, "port": port}
        if method == "stop": return self.core.request_shutdown()
        if method == "sync_peer":
            return {"accepted": self.core.sync_peer(p["host"], int(p["port"]),
                                                    int(p.get("batch", 128)))}
        raise RPCError("unknown method")


def _handler(dispatcher):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n <= 0 or n > 2 * 1024 * 1024:
                    raise RPCError("invalid request size")
                req = json.loads(self.rfile.read(n))
                if not isinstance(req, dict):
                    raise RPCError("request must be object")
                result = dispatcher.call(req.get("method"), req.get("params"))
                body = {"ok": True, "result": result}
                status = 200
            except Exception as e:
                body = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                status = 400
            raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    return Handler


class RPCServer:
    def __init__(self, core, host="127.0.0.1", port=0):
        # v0: intentionally loopback only.
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("RPC v0 may bind only to loopback")
        self.dispatcher = RPCDispatcher(core)
        self.httpd = ThreadingHTTPServer((host, int(port)), _handler(self.dispatcher))
        self.thread = None

    @property
    def address(self):
        return self.httpd.server_address

    def start(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.thread:
            self.thread.join(2)
