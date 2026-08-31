#!/usr/bin/env python3
"""SEC-219: hardened validators must not trust ambient/stale Python startup state."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent


def main() -> None:
    checks = 0

    windows = (ROOT / "validate_windows.ps1").read_text(encoding="utf-8")
    windows_lower = windows.lower()
    assert 'py -3.13 -i -s -c' in windows_lower
    assert 'py -3.13 -i -s -m venv .venv' in windows_lower
    assert 'if (-not (test-path ".venv"))' not in windows_lower
    assert 'get-item -literalpath $venvpath -force -erroraction silentlycontinue' in windows_lower
    assert '[io.fileattributes]::reparsepoint' in windows_lower
    assert 'remove-item -literalpath $venvpath -force' in windows_lower
    assert 'remove-item -literalpath $venvpath -recurse -force' in windows_lower
    assert windows_lower.index('remove-item -literalpath $venvpath') < windows_lower.index('py -3.13 -i -s -m venv .venv')
    checks += 1
    print("[GREEN] Windows validation isolates ambient Python and rebuilds rather than reusing .venv")

    posix = (ROOT / "validate_linux_macos.sh").read_text(encoding="utf-8")
    assert 'python3 -I -S -c' in posix
    assert 'python3 -I -S -m venv .venv' in posix
    assert 'if [[ ! -d .venv ]]' not in posix
    assert 'if [[ -L .venv ]]' in posix
    assert 'rm -- .venv' in posix
    assert 'rm -rf -- .venv' in posix
    assert posix.index('rm -rf -- .venv') < posix.index('python3 -I -S -m venv .venv')
    checks += 1
    print("[GREEN] POSIX validation removes stale runtime state before isolated venv creation")

    # The newly created venv is checked without importing site/sitecustomize.
    assert '& $Python -I -S -c' in windows
    assert '"$venv_python" -I -S -c' in posix
    checks += 1
    print("[GREEN] exact venv Python checks execute with site processing disabled")

    # Exercise the isolation flags themselves: neither PYTHONPATH nor a hostile
    # sitecustomize module may execute before the bootstrap command body.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        marker = root / "executed.txt"
        (root / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(root)
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", "import sys; raise SystemExit(0)"],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert not marker.exists()
    checks += 1
    print("[GREEN] -I -S bootstrap suppresses hostile PYTHONPATH/sitecustomize execution")

    # Rebuild must happen before the first ordinary (site-enabled) venv Python
    # use such as pip, doctor, validation, or receipt stamping.
    win_create = windows_lower.index('py -3.13 -i -s -m venv .venv')
    win_first_normal = windows_lower.index('& $python -m pip')
    assert win_create < win_first_normal
    posix_create = posix.index('python3 -I -S -m venv .venv')
    posix_first_normal = posix.index('"$venv_python" -m pip')
    assert posix_create < posix_first_normal
    checks += 1
    print("[GREEN] no normal site-enabled venv workload runs before clean reconstruction")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "validate_windows.ps1",
        "validate_linux_macos.sh",
        "security_sec219_clean_runtime_bootstrap_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest authenticates both validators and the SEC-219 regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-219 leaves canonical chain identity unchanged")

    assert checks == 7, checks
    print("SEC-219 clean runtime bootstrap: 7/7 GREEN")


if __name__ == "__main__":
    main()
