#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
spec_path = ROOT / "security_sec115_p2p_handshake_frame_budget_spec.py"
text = spec_path.read_text(encoding="utf-8")
old = '    assert len(checks) == 7\n    print("SEC-115 P2P handshake frame budget: 7/7 GREEN")\n'
new = '    assert len(checks) == 8\n    print("SEC-115 P2P handshake frame budget: 8/8 GREEN")\n'
if old not in text:
    raise SystemExit("SEC-115 count anchor not found")
spec_path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")

manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
data = spec_path.read_bytes()
manifest["files"][spec_path.name] = {
    "bytes": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
}
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
