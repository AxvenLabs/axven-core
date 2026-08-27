#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

P2P = Path("p2p.py")
SPEC = Path("security_sec100_p2p_propagation_ack_spec.py")
MANIFEST = Path("release_manifest.json")

text = P2P.read_text(encoding="utf-8")
anchor = '''def propagate_tx(address,tx):\n    sock=connect(address)\n    try:return request(sock,{"type":"tx","tx":tx.to_dict()})\n    finally:sock.close()\n\ndef propagate_block(address,block):\n    sock=connect(address)\n    try:return request(sock,{"type":"block","block":block.to_dict()})\n    finally:sock.close()\n'''
replacement = '''_BLOCK_ACK_STATUSES = {\n    "extended",\n    "reorg",\n    "side-chain",\n    "duplicate",\n    "orphan",\n}\n\ndef _validate_propagation_ack(reply,kind,expected_id):\n    if kind == "tx":\n        expected_fields={"type","kind","id"}\n    elif kind == "block":\n        expected_fields={"type","kind","id","status"}\n    else:\n        raise ValueError("unsupported propagation kind")\n    if set(reply) != expected_fields:\n        raise ProtocolError("invalid propagation acknowledgement fields")\n    if reply.get("type") != "accepted":\n        raise ProtocolError("expected propagation acknowledgement")\n    if reply.get("kind") != kind:\n        raise ProtocolError("propagation acknowledgement kind mismatch")\n    if reply.get("id") != expected_id:\n        raise ProtocolError("propagation acknowledgement id mismatch")\n    if kind == "block" and reply.get("status") not in _BLOCK_ACK_STATUSES:\n        raise ProtocolError("invalid block acknowledgement status")\n    return reply\n\ndef propagate_tx(address,tx):\n    sock=connect(address)\n    try:\n        reply=request(sock,{"type":"tx","tx":tx.to_dict()})\n        return _validate_propagation_ack(reply,"tx",tx.txid())\n    finally:sock.close()\n\ndef propagate_block(address,block):\n    sock=connect(address)\n    try:\n        reply=request(sock,{"type":"block","block":block.to_dict()})\n        return _validate_propagation_ack(reply,"block",block.hash())\n    finally:sock.close()\n'''
if anchor not in text:
    raise SystemExit("SEC-100 propagation anchor not found")
text = text.replace(anchor, replacement, 1)
with P2P.open("w", encoding="utf-8", newline="\n") as f:
    f.write(text)

spec = '''#!/usr/bin/env python3\n"""SEC-100 outbound P2P propagation acknowledgement contract."""\n\nimport p2p\n\n\ndef expect_rejected(reply, kind, expected_id):\n    try:\n        p2p._validate_propagation_ack(reply, kind, expected_id)\n    except p2p.ProtocolError:\n        return\n    raise AssertionError(f"malformed {kind} propagation acknowledgement accepted: {reply!r}")\n\n\ndef main():\n    txid = "11" * 32\n    blockid = "22" * 32\n\n    tx_ack = {"type": "accepted", "kind": "tx", "id": txid}\n    assert p2p._validate_propagation_ack(dict(tx_ack), "tx", txid) == tx_ack\n    print("[GREEN] canonical tx acknowledgement accepted")\n\n    block_ack = {\n        "type": "accepted",\n        "kind": "block",\n        "id": blockid,\n        "status": "extended",\n    }\n    assert p2p._validate_propagation_ack(dict(block_ack), "block", blockid) == block_ack\n    print("[GREEN] canonical block acknowledgement accepted")\n\n    malformed_tx = [\n        {"type": "status"},\n        {"type": "accepted", "kind": "block", "id": txid},\n        {"type": "accepted", "kind": "tx", "id": "00" * 32},\n        {"type": "accepted", "kind": "tx", "id": txid, "extra": True},\n        {"type": "accepted", "kind": "tx"},\n    ]\n    for reply in malformed_tx:\n        expect_rejected(reply, "tx", txid)\n    print("[GREEN] malformed tx acknowledgements rejected")\n\n    malformed_block = [\n        {"type": "accepted", "kind": "block", "id": blockid},\n        {"type": "accepted", "kind": "block", "id": blockid, "status": "forged"},\n        {"type": "accepted", "kind": "tx", "id": blockid, "status": "extended"},\n        {"type": "accepted", "kind": "block", "id": "00" * 32, "status": "extended"},\n        {"type": "accepted", "kind": "block", "id": blockid, "status": "extended", "extra": 1},\n    ]\n    for reply in malformed_block:\n        expect_rejected(reply, "block", blockid)\n    print("[GREEN] malformed block acknowledgements rejected")\n\n    for status in ("extended", "reorg", "side-chain", "duplicate", "orphan"):\n        reply = {"type": "accepted", "kind": "block", "id": blockid, "status": status}\n        p2p._validate_propagation_ack(reply, "block", blockid)\n    print("[GREEN] canonical block acknowledgement statuses preserved")\n    print("SEC-100 P2P propagation acknowledgement: 5/5 GREEN")\n\n\nif __name__ == "__main__":\n    main()\n'''
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

for temp in (Path("sec100_apply.py"), Path(".github/workflows/sec100_build.yml")):
    if temp.exists():
        temp.unlink()
