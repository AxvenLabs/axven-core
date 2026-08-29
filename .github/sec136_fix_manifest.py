#!/usr/bin/env python3
import hashlib
import json
import subprocess
from pathlib import Path

manifest_path=Path("release_manifest.json")
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("core.py","security_sec136_confirmed_tx_lookup_work_spec.py"):
    data=subprocess.check_output(["git","show",f"HEAD:{name}"])
    manifest["files"][name]={
        "bytes":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),
    }
with manifest_path.open("w",encoding="utf-8",newline="\n") as fh:
    fh.write(json.dumps(manifest,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
