from pathlib import Path
import hashlib
import json

tracked = (
    "axven.py",
    "security_sec112_sidechain_retention_bounds_spec.py",
)

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

for name in tracked:
    path = Path(name)
    data = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(data)
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
manifest_path.write_bytes(manifest_bytes)
