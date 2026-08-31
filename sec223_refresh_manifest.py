#!/usr/bin/env python3
"""Temporary SEC-223 manifest refresh helper; removed before PR."""
from pathlib import Path
import hashlib
import json

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
files = manifest["files"]
for name in (
    "core.py",
    "security_sec222_propagation_remote_provenance_spec.py",
    "security_sec223_bounded_propagation_fanout_spec.py",
):
    raw = Path(name).read_bytes()
    files[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
manifest["files"] = dict(sorted(files.items()))
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
