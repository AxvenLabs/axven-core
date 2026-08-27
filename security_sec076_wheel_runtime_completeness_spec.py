#!/usr/bin/env python3
"""SEC-076 wheel runtime module completeness contract."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="axven-sec076-") as td:
        td = Path(td)
        wheel_dir = td / "wheel"
        site_dir = td / "site"
        wheel_dir.mkdir()
        site_dir.mkdir()

        built = subprocess.run(
            [
                sys.executable, "-m", "pip", "wheel",
                "--no-deps", "--no-build-isolation",
                "-w", str(wheel_dir), ".",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        assert built.returncode == 0, built.stdout + built.stderr
        wheels = list(wheel_dir.glob("axven_core-*.whl"))
        assert len(wheels) == 1
        checks += 1
        print("[GREEN] wheel builds from repository metadata")

        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as zf:
            names = set(zf.namelist())
        assert "p2p_tx_bounds.py" in names
        checks += 1
        print("[GREEN] wheel contains p2p_tx_bounds runtime module")

        installed = subprocess.run(
            [
                sys.executable, "-m", "pip", "install",
                "--no-deps", "--target", str(site_dir), str(wheel),
            ],
            cwd=td,
            text=True,
            capture_output=True,
        )
        assert installed.returncode == 0, installed.stdout + installed.stderr
        checks += 1
        print("[GREEN] built wheel installs into isolated target")

        code = (
            "import sys;"
            f"sys.path.insert(0,{str(site_dir)!r});"
            "import p2p,p2p_tx_bounds;"
            "assert p2p.validate_tx_string_bounds is p2p_tx_bounds.validate_tx_string_bounds"
        )
        imported = subprocess.run(
            [sys.executable, "-I", "-c", code],
            cwd=td,
            text=True,
            capture_output=True,
        )
        assert imported.returncode == 0, imported.stdout + imported.stderr
        checks += 1
        print("[GREEN] installed wheel imports P2P runtime dependency")

    print(f"SEC-076 wheel runtime completeness: {checks}/4 GREEN")


if __name__ == "__main__":
    main()
