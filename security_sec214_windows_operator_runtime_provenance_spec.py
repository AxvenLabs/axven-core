#!/usr/bin/env python3
"""SEC-214: every Windows operator entrypoint must gate .venv Python on runtime provenance."""
from __future__ import annotations

import json
import re
from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
EXEMPT_RUNTIME_IMPLEMENTATIONS = {
    "ensure_runtime.ps1",
    "validate_windows.ps1",
}
EXPECTED_OPERATOR_ENTRYPOINTS = {
    "axven-console.cmd",
    "axven-console-node2.cmd",
    "start-node1.cmd",
    "start-node2.cmd",
    "start-public-p2p-node.cmd",
    "status-node1.cmd",
    "status-node2.cmd",
    "stop-node1.cmd",
    "stop-node2.cmd",
    "sync-node2-from-node1.cmd",
    "canonical_node1_start.ps1",
    "canonical_node2_start.ps1",
    "canonical_node1_mine1.ps1",
    "canonical_node1_status.ps1",
    "canonical_node2_sync_node1.ps1",
    "canonical_stop_all.ps1",
}
VENV_PYTHON_RE = re.compile(r"\.venv[\\/]+scripts[\\/]+python\.exe", re.IGNORECASE)


def _first_venv_python(text: str) -> int:
    match = VENV_PYTHON_RE.search(text)
    return -1 if match is None else match.start()


def main() -> None:
    checks = 0
    discovered: set[str] = set()

    candidates = sorted(ROOT.glob("*.cmd")) + sorted(ROOT.glob("*.ps1"))
    for path in candidates:
        text = path.read_text(encoding="utf-8-sig")
        lower = text.lower()
        python_pos = _first_venv_python(text)
        if python_pos < 0 or path.name in EXEMPT_RUNTIME_IMPLEMENTATIONS:
            continue

        discovered.add(path.name)
        gate_pos = lower.find("ensure_runtime.ps1")
        assert gate_pos >= 0, f"{path.name}: missing ensure_runtime.ps1 preflight"
        assert gate_pos < python_pos, f"{path.name}: runtime preflight occurs after first .venv Python execution"

        if path.suffix.lower() == ".cmd":
            between = lower[gate_pos:python_pos]
            assert "if errorlevel 1 exit /b 1" in between, (
                f"{path.name}: CMD launcher does not fail closed when provenance preflight fails"
            )
        else:
            assert '$erroractionpreference = "stop"' in lower[:python_pos], (
                f"{path.name}: PowerShell launcher is not fail-closed before Python execution"
            )

    assert EXPECTED_OPERATOR_ENTRYPOINTS.issubset(discovered), (
        "operator-entrypoint discovery unexpectedly missed: "
        + ", ".join(sorted(EXPECTED_OPERATOR_ENTRYPOINTS - discovered))
    )
    checks += 1
    print(f"[GREEN] {len(discovered)} Windows operator entrypoints gate .venv Python on runtime provenance")

    # Internal validation implementations are intentionally allowed to invoke the
    # candidate runtime while establishing/checking provenance; they are not
    # operator entrypoints and must stay narrowly enumerated here.
    for name in EXEMPT_RUNTIME_IMPLEMENTATIONS:
        text = (ROOT / name).read_text(encoding="utf-8-sig")
        assert _first_venv_python(text) >= 0
    checks += 1
    print("[GREEN] only the explicit validator/preflight implementations are exempt from operator gating")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    covered = manifest["files"]
    for name in EXPECTED_OPERATOR_ENTRYPOINTS | {
        "ensure_runtime.ps1",
        "runtime_provenance.py",
        "security_sec214_windows_operator_runtime_provenance_spec.py",
    }:
        assert name in covered, f"release manifest missing SEC-214 boundary file: {name}"
    checks += 1
    print("[GREEN] release manifest covers all operator provenance boundary files")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-214 leaves canonical chain identity unchanged")

    print(f"SEC-214 Windows operator runtime provenance: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
