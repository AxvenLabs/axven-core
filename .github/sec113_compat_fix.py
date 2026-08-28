from pathlib import Path
import hashlib
import json

spec_path = Path("security_sec071_p2p_message_type_bounds_spec.py")
source = spec_path.read_text(encoding="utf-8")
old = '    assert session.handle({"type": "status"}) is None\n'
new = '''    assert session.handle({
        "type": "status",
        "height": 0,
        "tip_hash": "0" * 64,
        "chainwork": 0,
    }) is None
'''
if source.count(old) != 1:
    raise SystemExit("SEC-113/071 compatibility anchor mismatch")
source = source.replace(old, new, 1).replace("\r\n", "\n")
spec_path.write_text(source, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in (
    "security_sec071_p2p_message_type_bounds_spec.py",
    "p2p.py",
    "security_sec113_p2p_status_envelope_spec.py",
):
    path = Path(name)
    data = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(data)
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
