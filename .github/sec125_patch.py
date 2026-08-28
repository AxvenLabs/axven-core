from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P2P = ROOT / "p2p.py"
SPEC = ROOT / "security_sec125_p2p_json_preparse_depth_spec.py"
MANIFEST = ROOT / "release_manifest.json"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"SEC-125 patch anchor {label!r}: expected 1, found {count}")
    return text.replace(old, new, 1)


text = P2P.read_text(encoding="utf-8").replace("\r\n", "\n")

text = replace_once(
    text,
    "MAX_INBOUND_MESSAGE_HOSTS = 1024\nMAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "MAX_INBOUND_MESSAGE_HOSTS = 1024\n"
    "# Canonical P2P envelopes are shallow, but Python's JSON parser otherwise\n"
    "# sees attacker-selected nesting before any message-specific validation or\n"
    "# post-handshake rate gate.  Reject pathological nesting in one linear raw\n"
    "# byte scan before json.loads.  This is transport parsing policy only.\n"
    "MAX_P2P_JSON_NESTING_DEPTH = 32\n"
    "MAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "depth constant",
)

preflight = r'''def _preflight_json_nesting(raw,max_depth=MAX_P2P_JSON_NESTING_DEPTH):
    """Bound JSON container nesting before allocating a decoded object graph."""
    if not isinstance(raw,(bytes,bytearray,memoryview)):
        raise ProtocolError("invalid json bytes")
    if type(max_depth) is not int or max_depth <= 0:
        raise ProtocolError("invalid json nesting limit")

    # Keep only opener bytes; the stack can never exceed max_depth because the
    # function fails immediately on the next opener.  JSON syntax itself is
    # still left to json.loads, including malformed/mismatched delimiters.
    stack=[]
    in_string=False
    escaped=False
    for value in raw:
        if in_string:
            if escaped:
                escaped=False
            elif value == 0x5C:  # backslash
                escaped=True
            elif value == 0x22:  # quote
                in_string=False
            continue

        if value == 0x22:  # quote
            in_string=True
            continue
        if value == 0x7B or value == 0x5B:  # { or [
            stack.append(value)
            if len(stack) > max_depth:
                raise ProtocolError("json nesting depth exceeded")
            continue
        if value == 0x7D:  # }
            if stack and stack[-1] == 0x7B:
                stack.pop()
            continue
        if value == 0x5D:  # ]
            if stack and stack[-1] == 0x5B:
                stack.pop()


'''
text = replace_once(
    text,
    "def _recv_message_with_lease(\n",
    preflight + "def _recv_message_with_lease(\n",
    "preflight helper",
)

text = replace_once(
    text,
    "        raw=_recv_exact(sock,n,deadline)\n        try:\n            msg=json.loads(raw,object_pairs_hook=_reject_duplicate_json_keys)\n",
    "        raw=_recv_exact(sock,n,deadline)\n"
    "        _preflight_json_nesting(raw)\n"
    "        try:\n"
    "            msg=json.loads(raw,object_pairs_hook=_reject_duplicate_json_keys)\n",
    "pre-parse wiring",
)

P2P.write_text(text, encoding="utf-8", newline="\n")

spec = r'''#!/usr/bin/env python3
"""SEC-125 bound P2P JSON nesting before json.loads."""

import inspect
import json
import socket
import struct

import axven
import p2p


def framed(raw: bytes) -> bytes:
    return struct.pack(">I", len(raw)) + raw


def recv_raw(raw: bytes, *, budget=None):
    left, right = socket.socketpair()
    try:
        left.sendall(framed(raw))
        if budget is None:
            return p2p.recv_message(right)
        return p2p._recv_message_with_lease(right, frame_byte_budget=budget)
    finally:
        left.close()
        right.close()


def main():
    checks=[]
    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "P2P raw JSON nesting limit pinned well above canonical wire depth",
        p2p.MAX_P2P_JSON_NESTING_DEPTH == 32,
    )

    # Top-level object counts as one container, so 31 nested arrays reaches the
    # exact depth-32 boundary and must still parse normally.
    at_limit = (
        b'{"type":"get_status","x":' + b'[' * 31 + b'0' + b']' * 31 + b'}'
    )
    parsed = recv_raw(at_limit)
    green(
        "exact nesting-depth boundary reaches normal JSON decode",
        isinstance(parsed, dict) and parsed.get("type") == "get_status",
    )

    too_deep = (
        b'{"type":"get_status","x":' + b'[' * 32 + b'0' + b']' * 32 + b'}'
    )
    parser_calls=[]
    original_loads=p2p.json.loads
    def trap_loads(*args, **kwargs):
        parser_calls.append(1)
        raise AssertionError("json.loads must not run for over-depth input")
    p2p.json.loads=trap_loads
    try:
        try:
            recv_raw(too_deep)
            over_depth_rejected=False
        except p2p.ProtocolError as exc:
            over_depth_rejected="nesting depth exceeded" in str(exc)
    finally:
        p2p.json.loads=original_loads
    green(
        "over-depth frame rejected before json.loads",
        over_depth_rejected and not parser_calls,
    )

    # Container-looking bytes inside strings must not affect depth.  Use
    # json.dumps so quotes/backslashes exercise real JSON escape sequences.
    string_payload = {
        "type":"get_status",
        "s": ("[{" * 80) + '\\\"quoted\\\\text' + ("}]" * 80),
    }
    string_raw=json.dumps(string_payload,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    p2p._preflight_json_nesting(string_raw)
    green(
        "brackets braces quotes and backslashes inside strings are ignored",
        True,
    )

    # Mismatched/unmatched closers must not drive depth negative and create a
    # bypass for a later deep opener run.  Syntax validity remains json.loads' job.
    try:
        p2p._preflight_json_nesting(b'}' * 64 + b'[' * 33)
        close_bypass_blocked=False
    except p2p.ProtocolError as exc:
        close_bypass_blocked="nesting depth exceeded" in str(exc)
    green(
        "unmatched closers cannot reset depth and bypass the limit",
        close_bypass_blocked,
    )

    # A mismatched closer does not pop an unlike opener either.
    try:
        p2p._preflight_json_nesting(b'{' + b']' * 64 + b'[' * 32)
        mismatch_bypass_blocked=False
    except p2p.ProtocolError as exc:
        mismatch_bypass_blocked="nesting depth exceeded" in str(exc)
    green(
        "mismatched closers cannot pop unlike openers",
        mismatch_bypass_blocked,
    )

    malformed = b'{"type":"get_status",]'
    p2p._preflight_json_nesting(malformed)
    try:
        recv_raw(malformed)
        malformed_failed=False
    except p2p.ProtocolError as exc:
        malformed_failed="invalid json" in str(exc)
    green(
        "ordinary malformed JSON remains fail-closed in the canonical parser",
        malformed_failed,
    )

    budget=p2p._InboundFrameByteBudget()
    try:
        recv_raw(too_deep,budget=budget)
        leased_reject=False
    except p2p.ProtocolError as exc:
        leased_reject="nesting depth exceeded" in str(exc)
    green(
        "preflight rejection releases SEC-122 frame lifetime reservation",
        leased_reject and budget.snapshot()["inflight_bytes"] == 0,
    )

    hello_raw=p2p._json_bytes(p2p.hello_message())
    p2p._preflight_json_nesting(hello_raw)
    green(
        "canonical handshake payload remains below pre-parse depth limit",
        len(hello_raw) <= p2p.MAX_HANDSHAKE_MESSAGE_BYTES,
    )

    wallet=axven.Wallet()
    chain=axven.Blockchain()
    chain.mine(wallet.address)
    server=p2p.NodeServer(chain,None,host="127.0.0.1",port=0)
    server.start()
    try:
        sock=p2p.connect(server.address)
        try:
            reply=p2p.request(sock,{"type":"get_status"})
        finally:
            sock.close()
        green(
            "healthy handshake and post-handshake request-reply remain available",
            reply.get("type") == "status" and reply.get("height") == chain.tip.height,
        )
    finally:
        server.stop()

    recv_src=inspect.getsource(p2p._recv_message_with_lease)
    green(
        "production receive path runs nesting preflight before json.loads",
        "_preflight_json_nesting(raw)" in recv_src
        and recv_src.index("_preflight_json_nesting(raw)") < recv_src.index("json.loads(raw"),
    )

    serve_src=inspect.getsource(p2p.serve_connection)
    server_src=inspect.getsource(p2p.NodeServer)
    green(
        "SEC-124 message gate and SEC-122 frame budget remain independently wired",
        "message_gate is not None and not message_gate()" in serve_src
        and "frame_byte_budget=self._frame_byte_budget" in server_src,
    )

    green(
        "preflight changes transport parsing only and leaves direct PeerSession semantics intact",
        p2p.PeerSession(chain,None).handle({"type":"get_status"}).get("type") == "status",
    )

    print(f"SEC-125 P2P JSON pre-parse depth: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
SPEC.write_text(spec.replace("\r\n", "\n"), encoding="utf-8", newline="\n")

manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (P2P,SPEC):
    raw=path.read_bytes().replace(b"\r\n",b"\n")
    path.write_bytes(raw)
    manifest["files"][path.name]={
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest,indent=2,sort_keys=True)+"\n",
    encoding="utf-8",
    newline="\n",
)
print("SEC-125 patch applied")
