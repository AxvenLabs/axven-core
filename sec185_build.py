#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

WORKFLOW=Path('.github/workflows/validation.yml')
MANIFEST=Path('release_manifest.json')
SPEC=Path('security_sec185_posix_security_ci_spec.py')

workflow='''name: Axven Validation

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
          python -m pip install "pip==26.2.1" "setuptools==84.0.0" "wheel==0.48.0" "packaging==26.3"
          python -m pip install -e .
          python -m pip check

      - name: Full validation
        shell: pwsh
        run: |
          python run_full_validation.py

      - name: SEC-076+ security tail
        shell: pwsh
        run: |
          python security_tail_runner.py

  posix-security:
    runs-on: ubuntu-latest

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

      - name: Install pinned packaging toolchain
        shell: bash
        run: |
          set -euo pipefail
          python -m pip install "pip==26.2.1" "setuptools==84.0.0" "wheel==0.48.0" "packaging==26.3"
          python -m pip install -e .
          python -m pip check

      - name: SEC-076+ security tail on POSIX
        shell: bash
        run: |
          set -euo pipefail
          python security_tail_runner.py
'''
WORKFLOW.write_text(workflow,encoding='utf-8',newline='\n')

spec='''#!/usr/bin/env python3
"""SEC-185: POSIX-specific hardening must execute on a real Linux CI lane."""
from __future__ import annotations

import os
from pathlib import Path

import axven


def main():
    text=Path('.github/workflows/validation.yml').read_text(encoding='utf-8')
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name)
        print(f"[GREEN] {name}")

    green('Windows validation lane preserved','runs-on: windows-latest' in text)
    green('real POSIX security lane present','posix-security:' in text and 'runs-on: ubuntu-latest' in text)
    green('POSIX lane runs security tail','SEC-076+ security tail on POSIX' in text and 'python security_tail_runner.py' in text)
    green('workflow remains read-only','permissions:\n  contents: read' in text)
    green('checkout remains immutable SHA pinned',text.count('actions/checkout@11d5960a326750d5838078e36cf38b85af677262')==2)
    green('setup-python remains immutable SHA pinned',text.count('actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065')==2)
    green('both checkouts drop credentials',text.count('persist-credentials: false')==2)
    green('both lanes pin Python 3.13.15',text.count('python-version: "3.13.15"')==2)
    green('both lanes pin pip',text.count('pip==26.2.1')==2)
    green('both lanes pin setuptools',text.count('setuptools==84.0.0')==2)
    green('both lanes pin wheel',text.count('wheel==0.48.0')==2)
    green('both lanes pin packaging',text.count('packaging==26.3')==2)
    if os.name=='posix':
        green('SEC-185 executes under real POSIX semantics',True)
    else:
        green('POSIX execution is enforced by dedicated Ubuntu job','runs-on: ubuntu-latest' in text)
    green('chain id unchanged',axven.CHAIN_ID=='axven-devnet-2')
    green('config fingerprint unchanged',axven.CONFIG_FINGERPRINT=='ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae')
    green('genesis unchanged',axven._genesis().hash()=='a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3')
    print(f"SEC-185 POSIX security CI: {len(checks)}/{len(checks)} GREEN")


if __name__=='__main__':
    main()
'''
SPEC.write_text(spec,encoding='utf-8',newline='\n')

manifest=json.loads(MANIFEST.read_text(encoding='utf-8'))
for path in (WORKFLOW,SPEC):
    raw=path.read_bytes()
    manifest['files'][path.as_posix()]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
MANIFEST.write_text(json.dumps(manifest,indent=2,sort_keys=True,ensure_ascii=False)+'\n',encoding='utf-8',newline='\n')
print('SEC-185 workflow/spec/manifest generated')
