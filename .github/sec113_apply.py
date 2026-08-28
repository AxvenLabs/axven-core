from pathlib import Path
import hashlib
import json

p2p_path = Path("p2p.py")
source = p2p_path.read_text(encoding="utf-8")
old = '        if typ=="status": return None\n'
new = '''        if typ=="status":
            expected_fields={"type","height","tip_hash","chainwork"}
            if set(msg) != expected_fields:
                raise ProtocolError("invalid status message fields")
            raw_height=msg.get("height")
            if type(raw_height) is not int or raw_height < 0:
                raise ProtocolError("invalid status height")
            raw_tip_hash=msg.get("tip_hash")
            if (
                not isinstance(raw_tip_hash,str)
                or len(raw_tip_hash) != 64
                or any(c not in "0123456789abcdef" for c in raw_tip_hash)
            ):
                raise ProtocolError("invalid status tip hash")
            raw_chainwork=msg.get("chainwork")
            if type(raw_chainwork) is not int or raw_chainwork < 0:
                raise ProtocolError("invalid status chainwork")
            return None
'''
if source.count(old) != 1:
    raise SystemExit("SEC-113 status anchor mismatch")
source = source.replace(old, new, 1).replace("\r\n", "\n")
p2p_path.write_text(source, encoding="utf-8", newline="\n")

spec = '''#!/usr/bin/env python3
"""SEC-113 canonical P2P status envelope and field domains."""

import axven
import p2p


def rejected(session, msg):
    try:
        session.handle(msg)
    except p2p.ProtocolError:
        return True
    return False


def main():
    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)
    canonical = session.status()

    assert set(canonical) == {"type", "height", "tip_hash", "chainwork"}
    assert session.handle(dict(canonical)) is None
    print("[GREEN] canonical status envelope preserved")

    for extra in (0, None, {}, [], {"nested": [1, 2, 3]}):
        bad = dict(canonical)
        bad["extra"] = extra
        assert rejected(session, bad)
    print("[GREEN] unknown status fields rejected")

    for field in ("height", "tip_hash", "chainwork"):
        bad = dict(canonical)
        bad.pop(field)
        assert rejected(session, bad)
    assert rejected(session, {"type": "status"})
    print("[GREEN] missing status fields rejected")

    for value in (True, -1, "0", 0.0, None):
        bad = dict(canonical)
        bad["height"] = value
        assert rejected(session, bad)
    print("[GREEN] status height domain enforced")

    for value in (None, 0, "0" * 63, "0" * 65, "g" * 64, "A" * 64):
        bad = dict(canonical)
        bad["tip_hash"] = value
        assert rejected(session, bad)
    print("[GREEN] status tip hash is canonical lowercase hex")

    for value in (True, -1, "1", 1.0, None):
        bad = dict(canonical)
        bad["chainwork"] = value
        assert rejected(session, bad)
    print("[GREEN] status chainwork domain enforced")

    source = PathLike = open(p2p.__file__, "r", encoding="utf-8").read()
    assert 'expected_fields={"type","height","tip_hash","chainwork"}' in source
    assert 'raise ProtocolError("invalid status message fields")' in source
    print("[GREEN] status validation wired before silent consume")

    print("SEC-113 canonical P2P status envelope: 6/6 GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = Path("security_sec113_p2p_status_envelope_spec.py")
spec_path.write_text(spec, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py", spec_path.name):
    data = Path(name).read_bytes().replace(b"\r\n", b"\n")
    Path(name).write_bytes(data)
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
