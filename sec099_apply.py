#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

P2P = Path("p2p.py")
SPEC = Path("security_sec099_p2p_get_status_fields_spec.py")
MANIFEST = Path("release_manifest.json")

text = P2P.read_text(encoding="utf-8")
old = '''        if typ=="status": return None\n        if typ=="get_status": return self.status()\n'''
new = '''        if typ=="status": return None\n        if typ=="get_status":\n            if any(key != "type" for key in msg):\n                raise ProtocolError("unknown get_status message field")\n            return self.status()\n'''
if old not in text:
    raise SystemExit("SEC-099 get_status anchor not found")
text = text.replace(old, new, 1)
with P2P.open("w", encoding="utf-8", newline="\n") as f:
    f.write(text)

spec = '''#!/usr/bin/env python3\n"""SEC-099 canonical P2P get_status envelope regression contract."""\n\nimport threading\n\nimport p2p\n\n\nclass FakeTip:\n    height = 7\n\n    def hash(self):\n        return "ab" * 32\n\n\nclass FakeChain:\n    def __init__(self):\n        self._state_lock = threading.RLock()\n        self.tip = FakeTip()\n        self.chainwork = 123\n\n\ndef rejected(session, message):\n    try:\n        session.handle(message)\n    except p2p.ProtocolError as exc:\n        assert str(exc) == "unknown get_status message field", exc\n        return\n    raise AssertionError("non-canonical get_status envelope accepted")\n\n\ndef main():\n    session = p2p.PeerSession(FakeChain())\n\n    for value in (None, True, 1, "x", [], {}, {"nested": [1, 2, 3]}):\n        rejected(session, {"type": "get_status", "extension": value})\n    print("[GREEN] get_status rejects unknown envelope fields")\n\n    reply = session.handle({"type": "get_status"})\n    assert reply == {\n        "type": "status",\n        "height": 7,\n        "tip_hash": "ab" * 32,\n        "chainwork": 123,\n    }\n    print("[GREEN] canonical get_status response preserved")\n    print("SEC-099 canonical P2P get_status fields: 2/2 GREEN")\n\n\nif __name__ == "__main__":\n    main()\n'''
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

for temp in (Path("sec099_apply.py"), Path(".github/workflows/sec099_build.yml")):
    if temp.exists():
        temp.unlink()
