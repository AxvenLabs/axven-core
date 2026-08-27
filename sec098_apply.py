#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

P2P = Path("p2p.py")
SPEC = Path("security_sec098_p2p_hello_fields_spec.py")
MANIFEST = Path("release_manifest.json")

text = P2P.read_text(encoding="utf-8")
old = '''def validate_handshake(msg: Dict[str, Any]) -> None:\n    expected=local_identity()\n    if msg.get("type") != "hello": raise ProtocolError("expected hello")\n    if type(msg.get("protocol_version")) is not int:\n        raise ProtocolError("protocol_version must be integer")\n    for key in ("protocol_version","chain_id","config_fingerprint","genesis_hash"):\n        if msg.get(key) != expected[key]:\n            raise ProtocolError(f"{key} mismatch")\n'''
new = '''_HELLO_FIELDS = {\n    "type",\n    "protocol_version",\n    "chain_id",\n    "config_fingerprint",\n    "genesis_hash",\n}\n\ndef validate_handshake(msg: Dict[str, Any]) -> None:\n    if any(key not in _HELLO_FIELDS for key in msg):\n        raise ProtocolError("unknown hello field")\n    expected=local_identity()\n    if msg.get("type") != "hello": raise ProtocolError("expected hello")\n    if type(msg.get("protocol_version")) is not int:\n        raise ProtocolError("protocol_version must be integer")\n    for key in ("protocol_version","chain_id","config_fingerprint","genesis_hash"):\n        if msg.get(key) != expected[key]:\n            raise ProtocolError(f"{key} mismatch")\n'''
if old not in text:
    raise SystemExit("SEC-098 handshake anchor not found")
text = text.replace(old, new, 1)
with P2P.open("w", encoding="utf-8", newline="\n") as f:
    f.write(text)

spec = '''#!/usr/bin/env python3\n"""SEC-098 canonical P2P hello-field regression contract."""\n\nimport socket\nimport threading\nimport time\n\nimport p2p\n\n\ndef expect_rejected(msg):\n    try:\n        p2p.validate_handshake(msg)\n    except p2p.ProtocolError:\n        return\n    raise AssertionError("hello message with unknown field was accepted")\n\n\ndef main():\n    canonical = p2p.hello_message()\n    p2p.validate_handshake(dict(canonical))\n    print("[GREEN] canonical hello accepted")\n\n    for value in (None, True, 1, "x", [], {}, {"nested": [1, 2, 3]}):\n        bad = dict(canonical)\n        bad["extension"] = value\n        expect_rejected(bad)\n    print("[GREEN] unknown hello fields rejected")\n\n    client, peer = socket.socketpair()\n    errors = []\n\n    def responder():\n        try:\n            received = p2p.recv_message(peer)\n            assert received == p2p.hello_message()\n            bad = p2p.hello_message()\n            bad["extension"] = {"ignored": True}\n            p2p.send_message(peer, bad)\n        except Exception as exc:\n            errors.append(exc)\n        finally:\n            peer.close()\n\n    thread = threading.Thread(target=responder, daemon=True)\n    thread.start()\n    try:\n        try:\n            p2p.handshake(client, deadline=time.monotonic() + 2.0)\n        except p2p.ProtocolError:\n            pass\n        else:\n            raise AssertionError("wire handshake accepted unknown hello field")\n    finally:\n        client.close()\n        thread.join(2.0)\n\n    assert not errors, errors\n    print("[GREEN] wire handshake enforces canonical hello fields")\n    print("SEC-098 canonical P2P hello fields: 3/3 GREEN")\n\n\nif __name__ == "__main__":\n    main()\n'''
with SPEC.open("w", encoding="utf-8", newline="\n") as f:
    f.write(spec)

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (P2P, SPEC):
    data = path.read_bytes()
    manifest["files"][path.name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
with MANIFEST.open("w", encoding="utf-8", newline="\n") as f:
    f.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")

for temp in (Path("sec098_apply.py"), Path(".github/workflows/sec098_build.yml")):
    if temp.exists():
        temp.unlink()
