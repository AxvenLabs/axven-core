#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

SOURCE = "origin/security-sec128-rpc-json-preparse-complexity"


def git_show(path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{SOURCE}:{path}"])


# Port only the already-reviewed RPC production patch from the stale experiment branch.
Path("rpc.py").write_bytes(git_show("rpc.py"))

old_spec = git_show("security_sec128_rpc_json_preparse_complexity_spec.py").decode("utf-8")
new_spec = old_spec.replace(
    '"""SEC-128 bound shallow RPC JSON fan-out before json.loads."""',
    '"""SEC-130 bound shallow RPC JSON fan-out before json.loads."""',
).replace(
    "SEC-128 RPC JSON pre-parse complexity:",
    "SEC-130 RPC JSON pre-parse complexity:",
)
if new_spec == old_spec:
    raise SystemExit("SEC-130 spec relabel failed")
Path("security_sec130_rpc_json_preparse_complexity_spec.py").write_text(
    new_spec, encoding="utf-8", newline="\n"
)

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
files = manifest["files"]
for name in ("rpc.py", "security_sec130_rpc_json_preparse_complexity_spec.py"):
    data = Path(name).read_bytes()
    files[name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest["files"] = dict(sorted(files.items()))
manifest_path.write_text(
    json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
)

subprocess.run([sys.executable, "security_sec130_rpc_json_preparse_complexity_spec.py"], check=True)
print("SEC-130 focused apply/test complete")
