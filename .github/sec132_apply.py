#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

P2P = Path("p2p.py")
MANIFEST = Path("release_manifest.json")
SPEC_PATH = Path("security_sec132_p2p_json_preparse_complexity_spec.py")
WORKFLOW = Path(".github/workflows/sec132-apply.yml")
SELF = Path(".github/sec132_apply.py")

text = P2P.read_text(encoding="utf-8")
old_constant = "MAX_P2P_JSON_NESTING_DEPTH = 32\nMAX_P2P_MESSAGE_TYPE_CHARS = 32"
new_constant = """MAX_P2P_JSON_NESTING_DEPTH = 32
# A 16 MiB frame can encode millions of shallow scalar/container entries.
# Bound decoded-object fan-out before json.loads while retaining generous
# headroom over any consensus-valid <=7 MiB block representation.
MAX_P2P_JSON_STRUCTURAL_ITEMS = 512 * 1024
MAX_P2P_MESSAGE_TYPE_CHARS = 32"""
if text.count(old_constant) != 1:
    raise SystemExit("SEC-132 constant anchor mismatch")
text = text.replace(old_constant, new_constant, 1)

old_func = '''def _preflight_json_nesting(raw,max_depth=MAX_P2P_JSON_NESTING_DEPTH):
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
new_func = '''def _preflight_json_nesting(
    raw,
    max_depth=MAX_P2P_JSON_NESTING_DEPTH,
    max_items=MAX_P2P_JSON_STRUCTURAL_ITEMS,
):
    """Bound JSON nesting and structural fan-out before parser allocation."""
    if not isinstance(raw,(bytes,bytearray,memoryview)):
        raise ProtocolError("invalid json bytes")
    if type(max_depth) is not int or max_depth <= 0:
        raise ProtocolError("invalid json nesting limit")
    if type(max_items) is not int or max_items <= 0:
        raise ProtocolError("invalid json structural limit")

    # Count each container plus each comma-separated member/item in the same
    # quote-aware pass used for nesting.  A flat attacker array therefore
    # consumes one unit per element without allocating the decoded list first.
    # JSON grammar validity remains json.loads' responsibility.
    stack=[]
    structural_items=0
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
            structural_items += 1
            if structural_items > max_items:
                raise ProtocolError("json structural complexity exceeded")
            stack.append(value)
            if len(stack) > max_depth:
                raise ProtocolError("json nesting depth exceeded")
            continue
        if value == 0x2C and stack:  # comma between members/items
            structural_items += 1
            if structural_items > max_items:
                raise ProtocolError("json structural complexity exceeded")
            continue
        if value == 0x7D:  # }
            if stack and stack[-1] == 0x7B:
                stack.pop()
            continue
        if value == 0x5D:  # ]
            if stack and stack[-1] == 0x5B:
                stack.pop()

'''
if text.count(old_func) != 1:
    raise SystemExit("SEC-132 preflight anchor mismatch")
text = text.replace(old_func, new_func, 1)
P2P.write_text(text, encoding="utf-8", newline="\n")

SPEC = r'''#!/usr/bin/env python3
"""SEC-132 bound shallow P2P JSON fan-out before json.loads."""

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


def flat_array(count):
    if count < 1:
        return b"[]"
    return b"[" + (b"0," * (count - 1)) + b"0]"


def main():
    checks=[]
    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    limit=p2p.MAX_P2P_JSON_STRUCTURAL_ITEMS
    green(
        "P2P raw structural budget is pinned with consensus-block headroom",
        limit == 512 * 1024
        and limit > (axven.CHAIN_CONFIG["max_block_bytes"] // 16),
    )

    # For a flat array the opener plus N-1 commas is exactly N structural
    # items, so the configured boundary is deterministic and cheap to test.
    p2p._preflight_json_nesting(flat_array(limit))
    green("exact raw structural-item boundary is accepted", True)

    over=flat_array(limit + 1)
    green(
        "shallow over-complex fixture remains below frame and depth caps",
        len(over) < p2p.MAX_MESSAGE_BYTES
        and p2p.MAX_P2P_JSON_NESTING_DEPTH >= 1,
    )

    parser_calls=[]
    original_loads=p2p.json.loads
    def trap_loads(*args, **kwargs):
        parser_calls.append(1)
        raise AssertionError("json.loads must not run for structural fan-out overflow")
    p2p.json.loads=trap_loads
    try:
        try:
            recv_raw(over)
            over_rejected=False
        except p2p.ProtocolError as exc:
            over_rejected="structural complexity exceeded" in str(exc)
    finally:
        p2p.json.loads=original_loads
    green(
        "shallow structural fan-out is rejected before json.loads",
        over_rejected and not parser_calls,
    )

    # Braces, brackets and commas inside JSON strings are data, not structure.
    string_payload={
        "type":"get_status",
        "s": ("[{,}]" * (limit // 4)),
    }
    string_raw=json.dumps(string_payload,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    green(
        "string-heavy fixture fits the transport byte cap",
        len(string_raw) < p2p.MAX_MESSAGE_BYTES,
    )
    p2p._preflight_json_nesting(string_raw)
    green("structural-looking bytes inside strings consume no fan-out budget", True)

    # A wide canonical-shaped transaction at both public vector boundaries is
    # comfortably below the parser fan-out gate.  This is transport headroom,
    # not a new transaction-validity rule.
    inp={
        "prev_txid":"0" * 64,
        "index":0,
        "signature":"A",
        "public_key":"A",
    }
    out={"amount":1,"recipient":"N" + "0" * 40}
    wide={
        "type":"tx",
        "tx":{
            "inputs":[inp] * p2p.MAX_P2P_TX_INPUTS,
            "outputs":[out] * p2p.MAX_P2P_TX_OUTPUTS,
        },
    }
    wide_raw=json.dumps(wide,separators=(",",":")).encode("utf-8")
    p2p._preflight_json_nesting(wide_raw)
    green(
        "maximum canonical-shaped transaction vectors retain wide headroom",
        len(wide_raw) < p2p.MAX_MESSAGE_BYTES,
    )

    budget=p2p._InboundFrameByteBudget()
    try:
        recv_raw(over,budget=budget)
        leased_reject=False
    except p2p.ProtocolError as exc:
        leased_reject="structural complexity exceeded" in str(exc)
    green(
        "fan-out rejection releases SEC-122 frame lifetime reservation",
        leased_reject and budget.snapshot()["inflight_bytes"] == 0,
    )

    hello_raw=p2p._json_bytes(p2p.hello_message())
    p2p._preflight_json_nesting(hello_raw)
    green(
        "canonical handshake remains below depth byte and fan-out budgets",
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

    preflight_src=inspect.getsource(p2p._preflight_json_nesting)
    green(
        "nesting and fan-out are enforced in one quote-aware linear scan",
        "structural_items += 1" in preflight_src
        and "json structural complexity exceeded" in preflight_src
        and "in_string" in preflight_src,
    )

    recv_src=inspect.getsource(p2p._recv_message_with_lease)
    green(
        "production receive path keeps preflight before json.loads",
        "_preflight_json_nesting(raw)" in recv_src
        and recv_src.index("_preflight_json_nesting(raw)") < recv_src.index("json.loads(raw"),
    )

    serve_src=inspect.getsource(p2p.serve_connection)
    server_src=inspect.getsource(p2p.NodeServer)
    green(
        "SEC-124 message gate and SEC-122 aggregate frame budget remain independent",
        "message_gate is not None and not message_gate()" in serve_src
        and "frame_byte_budget=self._frame_byte_budget" in server_src,
    )

    green(
        "P2P parser hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-132 P2P JSON pre-parse complexity: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
SPEC_PATH.write_text(SPEC, encoding="utf-8", newline="\n")

# The helper and privileged one-shot workflow must not survive on the clean
# branch. GitHub-token pushes do not recursively trigger workflows.
if WORKFLOW.exists():
    WORKFLOW.unlink()
if SELF.exists():
    SELF.unlink()

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (P2P, SPEC_PATH):
    data = path.read_bytes()
    manifest["files"][path.as_posix()] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
print("SEC-132 production patch, spec, and manifest staged")
