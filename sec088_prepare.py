#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
p2p_path = root / "p2p.py"
text = p2p_path.read_text(encoding="utf-8")


def replace_once(old, new, label):
    global text
    if text.count(old) != 1:
        raise SystemExit(f"SEC-088 patch anchor mismatch: {label} count={text.count(old)}")
    text = text.replace(old, new, 1)


replace_once(
    "import json, socket, struct, threading\n",
    "import json, socket, struct, threading, time\n",
    "time import",
)
replace_once(
    "INBOUND_PEER_TIMEOUT = 5.0\nMAX_INBOUND_PEERS = 32\n",
    "INBOUND_PEER_TIMEOUT = 5.0\nINBOUND_HANDSHAKE_TIMEOUT = 5.0\nMAX_INBOUND_PEERS = 32\n",
    "handshake timeout constant",
)
replace_once(
    '''def _recv_exact(sock,n):
    out=bytearray()
    while len(out)<n:
        chunk=sock.recv(n-len(out))
        if not chunk: raise EOFError("peer closed")
        out.extend(chunk)
    return bytes(out)

def recv_message(sock: socket.socket) -> Dict[str, Any]:
    n=struct.unpack(">I",_recv_exact(sock,4))[0]
    if n<=0 or n>MAX_MESSAGE_BYTES: raise ProtocolError("invalid message length")
    try:
        msg=json.loads(_recv_exact(sock,n),object_pairs_hook=_reject_duplicate_json_keys)
    except ProtocolError:
        raise
    except Exception as e:
        raise ProtocolError("invalid json") from e
    if not isinstance(msg,dict): raise ProtocolError("message must be object")
    return msg
''',
    '''def _recv_exact(sock,n,deadline=None):
    out=bytearray()
    while len(out)<n:
        if deadline is not None:
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise ProtocolError("handshake timeout")
            current=sock.gettimeout()
            if current is None or current>remaining:
                sock.settimeout(remaining)
        try:
            chunk=sock.recv(n-len(out))
        except socket.timeout as exc:
            if deadline is not None and time.monotonic()>=deadline:
                raise ProtocolError("handshake timeout") from exc
            raise
        if not chunk: raise EOFError("peer closed")
        out.extend(chunk)
    return bytes(out)

def recv_message(sock: socket.socket,deadline=None) -> Dict[str, Any]:
    n=struct.unpack(">I",_recv_exact(sock,4,deadline))[0]
    if n<=0 or n>MAX_MESSAGE_BYTES: raise ProtocolError("invalid message length")
    try:
        msg=json.loads(_recv_exact(sock,n,deadline),object_pairs_hook=_reject_duplicate_json_keys)
    except ProtocolError:
        raise
    except Exception as e:
        raise ProtocolError("invalid json") from e
    if not isinstance(msg,dict): raise ProtocolError("message must be object")
    return msg
''',
    "deadline-aware receive",
)
replace_once(
    '''def handshake(sock: socket.socket) -> Dict[str, Any]:
    send_message(sock,hello_message())
    peer=recv_message(sock)
    validate_handshake(peer)
    return peer
''',
    '''def handshake(sock: socket.socket,deadline=None) -> Dict[str, Any]:
    send_message(sock,hello_message())
    peer=recv_message(sock,deadline=deadline)
    validate_handshake(peer)
    return peer
''',
    "handshake deadline",
)
replace_once(
    '''def serve_connection(sock,session:PeerSession):
    try:
        handshake(sock)
        while True:
''',
    '''def serve_connection(sock,session:PeerSession):
    try:
        handshake_deadline=time.monotonic()+INBOUND_HANDSHAKE_TIMEOUT
        handshake(sock,deadline=handshake_deadline)
        sock.settimeout(INBOUND_PEER_TIMEOUT)
        while True:
''',
    "inbound deadline",
)

with p2p_path.open("w", encoding="utf-8", newline="\n") as f:
    f.write(text)

manifest_path = root / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py", "security_sec088_p2p_handshake_deadline_spec.py"):
    data = (root / name).read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    print(name, len(data), hashlib.sha256(data).hexdigest())

with manifest_path.open("w", encoding="utf-8", newline="\n") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
