#!/usr/bin/env python3
"""SEC-217: public bootstrap guidance must route through hardened provenance gates."""
from __future__ import annotations

import json
import re
from pathlib import Path

import axven


def main() -> None:
    checks = 0
    readme = Path("README.md").read_text(encoding="utf-8")
    readme_flat = " ".join(readme.split())
    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))

    assert "## Hardened first setup" in readme
    assert "hash-locked dependency artifacts" in readme
    assert "exact Python 3.13.15" in readme
    checks += 1
    print("[GREEN] public README advertises the hardened bootstrap contract")

    windows = readme.index("Windows:")
    setup = readme.index("run setup.cmd", windows)
    start = readme.index("run start-node1.cmd", setup)
    assert windows < setup < start
    assert "setup.cmd` delegates to the hardened Windows validator" in readme
    checks += 1
    print("[GREEN] Windows public bootstrap enters through setup.cmd before node start")

    assert "bash validate_linux_macos.sh" in readme
    assert "Do not replace these paths with `pip install --upgrade pip`" in readme
    checks += 1
    print("[GREEN] POSIX public bootstrap points to the hash-locked validator path")

    # A historical README block told users to execute an ExecutionPolicy bypass.
    # Mentioning the string as a prohibition is fine; executable fenced guidance is not.
    fenced_ps = re.findall(r"```(?:powershell|pwsh)\s*(.*?)```", readme, flags=re.I | re.S)
    assert not any("Set-ExecutionPolicy" in block and "Bypass" in block for block in fenced_ps)
    assert "On Windows PowerShell:" not in readme
    checks += 1
    print("[GREEN] public bootstrap no longer provides an executable policy-bypass recipe")

    assert "Windows quick start" not in readme
    assert "Both Windows and POSIX validation maintain platform-specific validated runtime-provenance receipts used by their operator launch paths." in readme_flat
    assert "axven-posix.sh` checks that receipt before the first operator Python process" in readme_flat
    checks += 1
    print("[GREEN] README does not present a provenance-blind Windows or POSIX quick-start path")

    files = manifest.get("files")
    assert isinstance(files, dict)
    assert "README.md" in files
    assert "security_sec217_public_bootstrap_provenance_spec.py" in files
    checks += 1
    print("[GREEN] release manifest covers SEC-217 public guidance and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-217 leaves canonical chain identity unchanged")

    print(f"SEC-217 public bootstrap provenance: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
