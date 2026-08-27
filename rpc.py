#!/usr/bin/env python3
"""Local JSON-RPC interface for Axven Core.

Default binding is loopback only.  This is intentionally not an Internet-facing
API; public authentication/TLS belongs to a later hardening milestone.
"""
from __future__ import annotations
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


RPC_REQUEST_TIMEOUT = 5.0
RPC_REQUEST_DEADLINE = 5.0
MAX_RPC_WORKERS = 32
MAX_RPC_REQUEST_BYTES = 2 * 1024 * 1024


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        self._worker_slots = threading.BoundedSemaphore(MAX_RPC_WORKERS)
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            try:
                self.shutdown_request(request)
            finally:
                self.close_request(request)
            return

        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class RPCError(ValueError): pass


_ALLOWED_RPC_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _require_safe_rpc_host(headers):
    values = headers.get_all("Host") or []
    if len(values) != 1:
        raise RPCError("invalid host header")

    authority = values[0].strip()
    if (
        not authority
        or any(ch in authority for ch in "/\\@ \t\r\n")
    ):
        raise RPCError("invalid host header")

    if authority.startswith("["):
        end = authority.find("]")
        if end <= 1:
            raise RPCError("invalid host header")
        host = authority[1:end].lower()
        suffix = authority[end + 1:]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                raise RPCError("invalid host header")
            port = int(suffix[1:])
            if not 1 <= port <= 65535:
                raise RPCError("invalid host header")
    else:
        if authority.count(":") > 1:
            raise RPCError("invalid host header")
        if ":" in authority:
            host, port_text = authority.rsplit(":", 1)
            if not port_text.isdigit():
                raise RPCError("invalid host header")
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise RPCError("invalid host header")
        else:
            host = authority
        host = host.lower()

    if host.endswith("."):
        host = host[:-1]
    if host not in _ALLOWED_RPC_HOSTS:
        raise RPCError("invalid host header")


def _require_rpc_int(value, label):
    if type(value) is not int:
        raise RPCError(f"{label} must be integer")
    return value


def _reject_duplicate_json_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise RPCError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _validate_param_depth(value, depth=0, budget=None):
    if budget is None:
        budget = [4096]

    budget[0] -= 1
    if budget[0] < 0:
        raise RPCError("params too complex")

    if depth > 16:
        raise RPCError("param nesting too deep")

    if isinstance(value, dict):
        for child in value.values():
            _validate_param_depth(child, depth + 1, budget)
    elif isinstance(value, list):
        for child in value:
            _validate_param_depth(child, depth + 1, budget)


class RPCDispatcher:
    def __init__(self, core):
        self.core = core

    def call(self, method, params=None):
        if not isinstance(method, str):
            raise RPCError("method must be string")
        if not method or len(method) > 256:
            raise RPCError("invalid method name")
        if params is not None and not isinstance(params, dict):
            raise RPCError("params must be object")
        if params is not None and len(params) > 64:
            raise RPCError("too many params")
        if params is not None:
            for key in params:
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise RPCError("invalid param key")
            budget = [4096]
            for value in params.values():
                _validate_param_depth(value, budget=budget)
        p = params or {}
        if method == "get_status": return self.core.status()
        if method == "get_overview": return self.core.overview()
        if method == "get_explorer_summary": return self.core.explorer_summary()
        if method == "get_recent_blocks":
            limit = _require_rpc_int(p.get("limit", 20), "recent blocks limit")
            if limit < 1 or limit > 200:
                raise RPCError("invalid recent blocks limit")
            return self.core.recent_blocks(limit)
        if method == "get_block": return self.core.get_block(p["id"])
        if method == "get_transaction": return self.core.get_transaction(p["txid"])
        if method == "get_mempool":
            limit = _require_rpc_int(p.get("limit", 100), "mempool limit")
            if limit < 1 or limit > 500:
                raise RPCError("invalid mempool limit")
            return self.core.mempool_view(limit)
        if method == "get_chain_config": return self.core.chain_config()
        if method == "get_addresses": return self.core.addresses()
        if method == "get_balance": return self.core.balance(p.get("scheme"))
        if method == "get_wallet_status": return self.core.wallet_status(p.get("scheme"))
        if method == "list_unspent": return self.core.list_unspent(p["scheme"])
        if method == "get_peers": return self.core.outbound_peer_status()
        if method == "get_peer_health": return self.core.peer_health_summary()
        if method == "add_peer":
            port = _require_rpc_int(p["port"], "peer port")
            if port < 1 or port > 65535:
                raise RPCError("invalid peer port")
            host, port = self.core.add_outbound_peer((p["host"], port))
            return {"host": host, "port": port}
        if method == "sync_peers":
            return self.core.sync_outbound_peers()
        if method == "remove_peer":
            port = _require_rpc_int(p["port"], "peer port")
            if port < 1 or port > 65535:
                raise RPCError("invalid peer port")
            return self.core.remove_outbound_peer((p["host"], port))
        if method == "mine":
            count = _require_rpc_int(p.get("count", 1), "mine count")
            if count <= 0 or count > 1000:
                raise RPCError("invalid mine count")
            return self.core.mine(count, p.get("scheme"))
        if method == "send":
            amount = _require_rpc_int(p["amount"], "send amount")
            fee = _require_rpc_int(p["fee"], "send fee")

            if amount <= 0 or amount > ((1 << 63) - 1):
                raise RPCError("invalid send amount")

            if fee < 0 or fee > ((1 << 63) - 1):
                raise RPCError("invalid send fee")

            return self.core.send(
                p["input_scheme"],
                p["recipient"],
                amount,
                fee,
            )
        if method == "start_p2p":
            port = _require_rpc_int(p.get("port", 0), "start_p2p port")
            if port < 0 or port > 65535:
                raise RPCError("invalid start_p2p port")
            h, port = self.core.start_p2p(
                p.get("host", "127.0.0.1"),
                port,
            )
            return {"host": h, "port": port}
        if method == "stop": return self.core.request_shutdown()
        if method == "sync_peer":
            batch = _require_rpc_int(p.get("batch", 128), "sync batch")
            if batch < 1 or batch > 128:
                raise RPCError("invalid sync batch")

            port = _require_rpc_int(p["port"], "sync peer port")
            if port < 1 or port > 65535:
                raise RPCError("invalid sync peer port")

            return {
                "accepted": self.core.sync_peer(
                    p["host"],
                    port,
                    batch,
                )
            }
        raise RPCError("unknown method")


def _handler(dispatcher):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(RPC_REQUEST_TIMEOUT)
            self._request_deadline_timer = threading.Timer(
                RPC_REQUEST_DEADLINE,
                self._expire_request,
            )
            self._request_deadline_timer.daemon = True
            self._request_deadline_timer.start()

        def _expire_request(self):
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def _cancel_request_deadline(self):
            timer = getattr(self, "_request_deadline_timer", None)
            if timer is not None:
                timer.cancel()
                self._request_deadline_timer = None

        def finish(self):
            self._cancel_request_deadline()
            try:
                super().finish()
            except OSError:
                pass

        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            self.connection.settimeout(RPC_REQUEST_TIMEOUT)
            try:
                _require_safe_rpc_host(self.headers)
                content_type = self.headers.get("Content-Type", "")
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type != "application/json":
                    raise RPCError("content type must be application/json")

                n = int(self.headers.get("Content-Length", "0"))
                if n <= 0 or n > MAX_RPC_REQUEST_BYTES:
                    raise RPCError("invalid request size")
                raw_request = self.rfile.read(n)
                if len(raw_request) != n:
                    raise RPCError("incomplete request body")
                self._cancel_request_deadline()
                req = json.loads(raw_request, object_pairs_hook=_reject_duplicate_json_keys)
                if not isinstance(req, dict):
                    raise RPCError("request must be object")

                unknown_fields = set(req) - {"method", "params"}
                if unknown_fields:
                    raise RPCError(
                        "unknown request field: "
                        + sorted(unknown_fields)[0]
                    )

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
        self.httpd = BoundedThreadingHTTPServer((host, int(port)), _handler(self.dispatcher))
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
