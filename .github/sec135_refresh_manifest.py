#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

manifest_path=Path("release_manifest.json")
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
files=manifest["files"]

for name in (
    "explorer.py",
    "security_sec135_explorer_host_header_guard_spec.py",
):
    raw=Path(name).read_bytes()
    files[name]={
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
    }

manifest_path.write_text(
    json.dumps(manifest,indent=2,sort_keys=True,ensure_ascii=False)+"\n",
    encoding="utf-8",
)
