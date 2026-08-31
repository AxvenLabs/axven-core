#!/usr/bin/env python3
"""SEC-218: POSIX operator commands require validated runtime provenance."""
from __future__ import annotations

import tempfile
from pathlib import Path

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


def _write_inputs(root: Path, names: tuple[str, ...]) -> None:
    for index, name in enumerate(names):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"trusted-{index}\n".encode("utf-8"))


def main() -> None:
    checks = 0

    assert runtime_provenance._active_trust_inputs("Windows") == runtime_provenance.TRUST_INPUTS
    assert runtime_provenance._active_trust_inputs("Linux") == runtime_provenance.POSIX_TRUST_INPUTS
    assert runtime_provenance._active_trust_inputs("Darwin") == runtime_provenance.POSIX_TRUST_INPUTS
    assert "requirements-ci-runtime-windows.lock" in runtime_provenance.TRUST_INPUTS
    assert "requirements-ci-runtime-posix.lock" in runtime_provenance.POSIX_TRUST_INPUTS
    assert "validate_linux_macos.sh" in runtime_provenance.POSIX_TRUST_INPUTS
    assert "ensure_runtime.sh" in runtime_provenance.POSIX_TRUST_INPUTS
    checks += 1
    print("[GREEN] Windows provenance is preserved and POSIX has a distinct trust-input contract")

    try:
        runtime_provenance._active_trust_inputs("Plan9")
    except RuntimeError:
        pass
    else:
        raise AssertionError("runtime provenance accepted an unsupported platform")
    checks += 1
    print("[GREEN] runtime provenance fails closed on unsupported platforms")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write_inputs(root, runtime_provenance.POSIX_TRUST_INPUTS)
        first = runtime_provenance.build_receipt(
            root,
            python_version=runtime_provenance.REQUIRED_PYTHON,
            trust_inputs=runtime_provenance.POSIX_TRUST_INPUTS,
        )
        assert set(first["inputs"]) == set(runtime_provenance.POSIX_TRUST_INPUTS)
        changed = root / "requirements-ci-runtime-posix.lock"
        changed.write_bytes(b"tampered-posix-lock\n")
        second = runtime_provenance.build_receipt(
            root,
            python_version=runtime_provenance.REQUIRED_PYTHON,
            trust_inputs=runtime_provenance.POSIX_TRUST_INPUTS,
        )
        assert first != second
    checks += 1
    print("[GREEN] POSIX receipt is bound to the POSIX hash-lock/runtime trust state")

    provenance_source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    assert "Path(sys.prefix).resolve()" in provenance_source
    assert "trust_inputs=_active_trust_inputs()" in provenance_source
    checks += 1
    print("[GREEN] receipt management supports symlinked POSIX venv interpreters and active platform inputs")

    validator = (ROOT / "validate_linux_macos.sh").read_text(encoding="utf-8")
    assert "requirements-ci-runtime-posix.lock" in validator
    assert "security_tail_runner.py" in validator
    assert "runtime_provenance.py\" stamp" in validator
    assert validator.index("security_tail_runner.py") < validator.index("runtime_provenance.py\" stamp")
    assert validator.index("runtime_provenance.py\" stamp") < validator.index("ALL AXVEN CHECKS GREEN")
    checks += 1
    print("[GREEN] POSIX validator stamps provenance only after the complete security gate")

    ensure = (ROOT / "ensure_runtime.sh").read_text(encoding="utf-8")
    assert "runtime_provenance.py check" in ensure
    assert "doctor.py" in ensure
    assert "bash validate_linux_macos.sh" in ensure
    assert "pip install" not in ensure
    assert "source .venv/bin/activate" not in ensure
    checks += 1
    print("[GREEN] POSIX preflight checks receipt + doctor and repairs only through hardened validation")

    runbook = (ROOT / "RUNBOOK.md").read_text(encoding="utf-8")
    assert "exact Python 3.13.15" in runbook
    assert "bash validate_linux_macos.sh" in runbook
    assert "bash ensure_runtime.sh" in runbook
    assert "python -m pip install --upgrade pip" not in runbook
    assert "python -m pip install -e ." not in runbook
    checks += 1
    print("[GREEN] runbook no longer advertises ambient dependency resolution")

    seed_ops = (ROOT / "SEED_OPERATIONS.md").read_text(encoding="utf-8")
    assert "ensure_runtime.ps1" in seed_ops
    assert seed_ops.count("bash ensure_runtime.sh") >= 2
    assert "source .venv/bin/activate" not in seed_ops
    assert "do not source `.venv/bin/activate`" in seed_ops.lower()
    checks += 1
    print("[GREEN] seed health and VPS operator commands are provenance-gated")

    import json
    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "validate_linux_macos.sh",
        "ensure_runtime.sh",
        "RUNBOOK.md",
        "SEED_OPERATIONS.md",
        "security_sec218_posix_operator_runtime_provenance_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers every SEC-218 operator-provenance artifact")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-218 leaves canonical chain identity unchanged")

    print(f"SEC-218 POSIX operator runtime provenance: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
