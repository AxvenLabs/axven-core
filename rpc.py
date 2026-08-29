#!/usr/bin/env python3
"""Local JSON-RPC interface for Axven Core.

Default binding is loopback only.  This is intentionally not an Internet-facing
API; public authentication/TLS belongs to a later hardening milestone.
"""
from __future__ import annotations
import hmac
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


RPC_REQUEST_TIMEOUT = 5.0
RPC_REQUEST_DEADLINE = 5.0
MAX_RPC_WORKERS = 32
MAX_RPC_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RPC_JSON_NESTING_DEPTH = 32
MAX_RPC_PARAM_NODES = 4096
MAX_RPC_JSON_STRUCTURAL_ITEMS = 2 * MAX_RPC_PARAM_NODES


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    # ThreadingHTTPServer defaults request workers to daemon threads, which
    # means ThreadingMixIn.server_close() does not join them.  RPC handlers can
    # mutate chain state (mine/send/sync), so graceful shutdown must wait for
    # every admitted handler before final persistence may be considered safe.
    daemon_threads = False
    block_on_close = True

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
class RPCAuthError(RPCError): pass


_ALLOWED_RPC_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _validate_rpc_auth_token(token):
    if type(token) is not str or len(token)!=64:
        raise ValueError("RPC auth token must be 64 lowercase hex characters")
    if any(ch not in "0123456789abcdef" for ch in token):
        raise ValueError("RPC auth token must be 64 lowercase hex characters")
    return token


def _require_rpc_authorization(headers, expected_token):
    if expected_token is None:
        return
    values=headers.get_all("Authorization") or []
    if len(values)!=1:
        raise RPCAuthError("RPC authorization required")
    value=values[0]
    prefix="Bearer "
    if not value.startswith(prefix):
        raise RPCAuthError("RPC authorization failed")
    provided=value[len(prefix):]
    if len(provided)!=64 or not hmac.compare_digest(provided,expected_token):
        raise RPCAuthError("RPC authorization failed")


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


def _require_rpc_request_framing(headers):
    # The RPC server accepts one fixed-length JSON body only.  Reject HTTP
    # framing aliases before reading a body so duplicate lengths or transfer
    # codings cannot create parser/proxy disagreement around operator calls.
    transfer_values = headers.get_all("Transfer-Encoding") or []
    if transfer_values:
        raise RPCError("transfer encoding not supported")

    content_types = headers.get_all("Content-Type") or []
    if len(content_types) != 1:
        raise RPCError("invalid content type header")
    media_type = content_types[0].split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise RPCError("content type must be application/json")

    lengths = headers.get_all("Content-Length") or []
    if len(lengths) != 1:
        raise RPCError("invalid content length header")
    length_text = lengths[0].strip()
    if (
        not length_text
        or len(length_text) > 10
        or not length_text.isascii()
        or not length_text.isdigit()
    ):
        raise RPCError("invalid request size")

    n = int(length_text)
    if n <= 0 or n > MAX_RPC_REQUEST_BYTES:
        raise RPCError("invalid request size")
    return n


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


def _preflight_json_nesting(raw):
    """Bound raw JSON nesting and structural fan-out before parser allocation."""
    stack = []
    structural_items = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
            continue

        if byte == 0x22:
            in_string = True
            continue
        if byte in (0x7B, 0x5B):  # { [
            structural_items += 1
            if structural_items > MAX_RPC_JSON_STRUCTURAL_ITEMS:
                raise RPCError("JSON structural complexity exceeded")
            stack.append(byte)
            if len(stack) > MAX_RPC_JSON_NESTING_DEPTH:
                raise RPCError("JSON nesting depth exceeded")
            continue
        if byte == 0x2C and stack:  # comma between container members/items
            structural_items += 1
            if structural_items > MAX_RPC_JSON_STRUCTURAL_ITEMS:
                raise RPCError("JSON structural complexity exceeded")
            continue
        if byte in (0x7D, 0x5D):  # } ]
            expected = 0x7B if byte == 0x7D else 0x5B
            if stack and stack[-1] == expected:
                stack.pop()


def _validate_param_depth(value, depth=0, budget=None):
    if budget is None:
        budget = [MAX_RPC_PARAM_NODES]

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


# SEC-169: each RPC method has one canonical parameter vocabulary.  Global
# structural bounds are necessary but not sufficient: silently ignored fields
# create semantic aliases and can hide client/operator mistakes around mutating
# calls.  Keep required/optional shape validation ahead of core dispatch.
_RPC_METHOD_PARAM_SCHEMA = {
    "get_status": (frozenset(), frozenset()),
    "get_overview": (frozenset(), frozenset()),
    "get_explorer_summary": (frozenset(), frozenset()),
    "get_recent_blocks": (frozenset({"limit"}), frozenset()),
    "get_block": (frozenset({"id"}), frozenset({"id"})),
    "get_transaction": (frozenset({"txid"}), frozenset({"txid"})),
    "get_mempool": (frozenset({"limit"}), frozenset()),
    "get_chain_config": (frozenset(), frozenset()),
    "get_addresses": (frozenset(), frozenset()),
    "get_balance": (frozenset({"scheme"}), frozenset()),
    "get_wallet_status": (frozenset({"scheme"}), frozenset()),
    "list_unspent": (frozenset({"scheme"}), frozenset({"scheme"})),
    "get_peers": (frozenset(), frozenset()),
    "get_peer_health": (frozenset(), frozenset()),
    "add_peer": (frozenset({"host", "port"}), frozenset({"host", "port"})),
    "sync_peers": (frozenset(), frozenset()),
    "remove_peer": (frozenset({"host", "port"}), frozenset({"host", "port"})),
    "mine": (frozenset({"count", "scheme"}), frozenset()),
    "send": (
        frozenset({"input_scheme", "recipient", "amount", "fee"}),
        frozenset({"input_scheme", "recipient", "amount", "fee"}),
    ),
    "start_p2p": (frozenset({"host", "port"}), frozenset()),
    "stop": (frozenset(), frozenset()),
    "sync_peer": (
        frozenset({"host", "port", "batch"}),
        frozenset({"host", "port"}),
    ),
}


def _require_rpc_method_params(method, params):
    schema = _RPC_METHOD_PARAM_SCHEMA.get(method)
    if schema is None:
        raise RPCError("unknown method")
    allowed, required = schema
    unknown = set(params) - allowed
    if unknown:
        raise RPCError(f"unknown RPC param: {sorted(unknown)[0]}")
    missing = required - set(params)
    if missing:
        raise RPCError(f"missing RPC param: {sorted(missing)[0]}")
    return params


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
            budget = [MAX_RPC_PARAM_NODES]
            for value in params.values():
                _validate_param_depth(value, budget=budget)
        p = params or {}
        _require_rpc_method_params(method, p)
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


def _handler(dispatcher, auth_token=None):
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
                _require_rpc_authorization(self.headers,auth_token)
                n = _require_rpc_request_framing(self.headers)
                raw_request = self.rfile.read(n)
                if len(raw_request) != n:
                    raise RPCError("incomplete request body")
                self._cancel_request_deadline()
                _preflight_json_nesting(raw_request)
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


def _validate_rpc_listener_endpoint(host, port):
    if type(host) is not str:
        raise ValueError("RPC listener host must be string")
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("RPC v0 may bind only to loopback")
    if type(port) is not int:
        raise ValueError("RPC listener port must be integer")
    if port < 0 or port > 65535:
        raise ValueError("invalid RPC listener port")
    return host, port


class RPCServer:
    def __init__(self, core, host="127.0.0.1", port=0, auth_token=None):
        # v0: intentionally loopback only.  Production daemon also supplies a
        # per-datadir bearer token; None remains an explicit in-process/test mode.
        host, port = _validate_rpc_listener_endpoint(host, port)
        self.auth_token=(
            None if auth_token is None else _validate_rpc_auth_token(auth_token)
        )
        self.dispatcher = RPCDispatcher(core)
        self.httpd = BoundedThreadingHTTPServer(
            (host, port), _handler(self.dispatcher,self.auth_token)
        )
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
