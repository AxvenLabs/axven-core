#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SPEC = Path("security_sec126_peer_config_resource_bounds_spec.py")
MANIFEST = Path("release_manifest.json")
WORKFLOW = Path(".github/workflows/validation.yml")
SELF = Path(__file__)

OLD = '''    load_src=inspect.getsource(DataDir.load_peers)\n    save_src=inspect.getsource(DataDir.save_peers)\n    core_src=(Path(__file__).resolve().parent / "core.py").read_text(encoding="utf-8")\n    green(\n        "production persistence path bounds read count save count and payload bytes",\n        "f.read(MAX_PEER_CONFIG_BYTES + 1)" in load_src\n        and "len(raw) > AxvenCore.MAX_CONFIGURED_PEERS" in load_src\n        and "len(normalized) >= AxvenCore.MAX_CONFIGURED_PEERS" in save_src\n        and "len(payload) > MAX_PEER_CONFIG_BYTES" in save_src,\n    )\n'''
NEW = '''    load_src=inspect.getsource(DataDir.load_peers)\n    secure_read_src=inspect.getsource(datadir._read_secure_peer_config_file)\n    save_src=inspect.getsource(DataDir.save_peers)\n    core_src=(Path(__file__).resolve().parent / "core.py").read_text(encoding="utf-8")\n    green(\n        "production persistence path bounds read count save count and payload bytes",\n        "_read_secure_peer_config_file(self.peer_file)" in load_src\n        and "f.read(MAX_PEER_CONFIG_BYTES+1)" in secure_read_src\n        and "len(raw) > AxvenCore.MAX_CONFIGURED_PEERS" in load_src\n        and "len(normalized) >= AxvenCore.MAX_CONFIGURED_PEERS" in save_src\n        and "len(payload) > MAX_PEER_CONFIG_BYTES" in save_src,\n    )\n'''

CANONICAL_WORKFLOW = '''name: Axven Validation

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: windows-latest

    env:
      PYTHONUTF8: "1"
      PYTHONIOENCODING: "utf-8"

    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false

      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with:
          python-version: "3.13.15"

      - name: Enable UTF-8
        shell: pwsh
        run: |
          chcp 65001

      - name: Install pinned packaging toolchain
        shell: pwsh
        run: |
          python -m pip install "pip==26.2.1" "setuptools==84.0.0" "wheel==0.48.0"
          python -m pip install -e .

      - name: Full validation
        shell: pwsh
        run: |
          python run_full_validation.py

      - name: SEC-076+ security tail
        shell: pwsh
        run: |
          python security_tail_runner.py
'''

text = SPEC.read_text(encoding="utf-8")
if OLD in text:
    text = text.replace(OLD, NEW, 1)
elif NEW not in text:
    raise SystemExit("SEC-126 repair anchor not found")
SPEC.write_text(text, encoding="utf-8", newline="\n")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
raw = SPEC.read_bytes()
manifest["files"][SPEC.as_posix()] = {
    "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(),
}
MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

WORKFLOW.write_text(CANONICAL_WORKFLOW, encoding="utf-8", newline="\n")
SELF.unlink()
