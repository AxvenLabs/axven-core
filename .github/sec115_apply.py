#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
p2p_path = ROOT / "p2p.py"
text = p2p_path.read_text(encoding="utf-8")

old = "PROTOCOL_VERSION = 2\nMAX_MESSAGE_BYTES = 16 * 1024 * 1024\nINBOUND_PEER_TIMEOUT = 5.0\n"
new = "PROTOCOL_VERSION = 2\nMAX_MESSAGE_BYTES = 16 * 1024 * 1024\nMAX_HANDSHAKE_MESSAGE_BYTES = 4 * 1024\nINBOUND_PEER_TIMEOUT = 5.0\n"
if old not in text:
    raise SystemExit("SEC-115 constant anchor not found")
text = text.replace(old, new, 1)

old = '''def recv_message(sock: socket.socket,deadline=None) -> Dict[str, Any]:
    n=struct.unpack(">I",_recv_exact(sock,4,deadline))[0]
    if n<=0 or n>MAX_MESSAGE_BYTES: raise ProtocolError("invalid message length")
    try:
        msg=json.loads(_recv_exact(sock,n,deadline),object_pairs_hook=_reject_duplicate_json_keys)
'''
new = '''def recv_message(sock: socket.socket,deadline=None,max_bytes=None) -> Dict[str, Any]:
    frame_limit=MAX_MESSAGE_BYTES if max_bytes is None else max_bytes
    if type(frame_limit) is not int or frame_limit <= 0:
        raise ProtocolError("invalid message byte limit")
    n=struct.unpack(">I",_recv_exact(sock,4,deadline))[0]
    if n<=0 or n>frame_limit: raise ProtocolError("invalid message length")
    try:
        msg=json.loads(_recv_exact(sock,n,deadline),object_pairs_hook=_reject_duplicate_json_keys)
'''
if old not in text:
    raise SystemExit("SEC-115 recv_message anchor not found")
text = text.replace(old, new, 1)

old = '''def handshake(sock: socket.socket,deadline=None) -> Dict[str, Any]:
    send_message(sock,hello_message())
    peer=recv_message(sock,deadline=deadline)
    validate_handshake(peer)
'''
new = '''def handshake(sock: socket.socket,deadline=None) -> Dict[str, Any]:
    send_message(sock,hello_message())
    peer=recv_message(
        sock,
        deadline=deadline,
        max_bytes=MAX_HANDSHAKE_MESSAGE_BYTES,
    )
    validate_handshake(peer)
'''
if old not in text:
    raise SystemExit("SEC-115 handshake anchor not found")
text = text.replace(old, new, 1)
p2p_path.write_text(text, encoding="utf-8", newline="\n")

spec = r'''#!/usr/bin/env python3
"""SEC-115 bounds pre-handshake P2P frames independently of block-sync frames."""

import socket
import struct
import threading
import time

import axven
import p2p


class PrefixOnlySocket:
    def __init__(self, advertised_length):
        self._prefix = bytearray(struct.pack(">I", advertised_length))
        self.body_read = False
        self._timeout = None

    def recv(self, count):
        if self._prefix:
            chunk = bytes(self._prefix[:count])
            del self._prefix[:count]
            return chunk
        self.body_read = True
        raise AssertionError("oversized handshake attempted to read frame body")

    def gettimeout(self):
        return self._timeout

    def settimeout(self, value):
        self._timeout = value


def wait_until(fn, timeout=1.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return True
        time.sleep(0.02)
    return fn()


def client_count(server):
    with server._lock:
        return len(server._clients)


def main():
    checks = []

    def ok(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    hello_bytes = p2p._json_bytes(p2p.hello_message())
    ok(
        "handshake byte budget is small and canonical hello fits",
        len(hello_bytes) < p2p.MAX_HANDSHAKE_MESSAGE_BYTES
        == 4 * 1024
        < p2p.MAX_MESSAGE_BYTES,
    )

    prefix_only = PrefixOnlySocket(p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 1)
    try:
        p2p.recv_message(
            prefix_only,
            max_bytes=p2p.MAX_HANDSHAKE_MESSAGE_BYTES,
        )
    except p2p.ProtocolError:
        pass
    else:
        raise AssertionError("oversized handshake frame accepted")
    ok(
        "oversized handshake rejected before body read",
        not prefix_only.body_read,
    )

    left, right = socket.socketpair()
    try:
        payload = {
            "type": "padding",
            "padding": "x" * (p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 512),
        }
        raw_size = len(p2p._json_bytes(payload))
        assert p2p.MAX_HANDSHAKE_MESSAGE_BYTES < raw_size < p2p.MAX_MESSAGE_BYTES
        p2p.send_message(right, payload)
        received = p2p.recv_message(left)
        ok(
            "post-handshake general frame budget remains available",
            received == payload,
        )
    finally:
        left.close()
        right.close()

    client, peer = socket.socketpair()
    responder_errors = []

    def oversized_responder():
        try:
            received = p2p.recv_message(peer)
            p2p.validate_handshake(received)
            peer.sendall(
                struct.pack(">I", p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 1)
            )
        except Exception as exc:
            responder_errors.append(exc)
        finally:
            peer.close()

    thread = threading.Thread(target=oversized_responder, daemon=True)
    thread.start()
    try:
        try:
            p2p.handshake(client, deadline=time.monotonic() + 1.0)
        except p2p.ProtocolError:
            pass
        else:
            raise AssertionError("outbound handshake accepted oversized peer hello")
    finally:
        client.close()
        thread.join(1.0)
    ok(
        "outbound handshake enforces pre-auth frame budget",
        not responder_errors and not thread.is_alive(),
    )

    chain = axven.Blockchain()
    mempool = axven.Mempool(chain)
    server = p2p.NodeServer(chain, mempool).start()
    attacker = None
    try:
        attacker = socket.create_connection(server.address, timeout=1)
        attacker.settimeout(1)
        server_hello = p2p.recv_message(attacker)
        p2p.validate_handshake(server_hello)
        ok(
            "oversized pre-handshake peer registered",
            wait_until(lambda: client_count(server) == 1),
        )
        attacker.sendall(
            struct.pack(">I", p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 1)
        )
        ok(
            "inbound oversized handshake is disconnected",
            wait_until(lambda: client_count(server) == 0),
        )
        attacker.close()
        attacker = None

        healthy = p2p.connect(server.address, timeout=1)
        try:
            status = p2p.request(healthy, {"type": "get_status"})
            ok(
                "listener survives oversized pre-auth frame",
                status["tip_hash"] == chain.tip.hash(),
            )
        finally:
            healthy.close()
    finally:
        if attacker is not None:
            try:
                attacker.close()
            except OSError:
                pass
        server.stop()

    source = open(p2p.__file__, "r", encoding="utf-8").read()
    ok(
        "handshake receive is explicitly wired to small frame cap",
        "max_bytes=MAX_HANDSHAKE_MESSAGE_BYTES" in source,
    )

    assert len(checks) == 7
    print("SEC-115 P2P handshake frame budget: 7/7 GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = ROOT / "security_sec115_p2p_handshake_frame_budget_spec.py"
spec_path.write_text(spec, encoding="utf-8", newline="\n")

manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py", spec_path.name):
    path = ROOT / name
    data = path.read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
