#!/usr/bin/env python3
"""SEC-218: POSIX validation must produce platform-bound runtime provenance."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


def _populate(root: Path, names: tuple[str, ...]) -> None:
    for index, name in enumerate(names):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"trusted-{index}\n".encode("utf-8"))


def main() -> None:
    checks = 0

    assert runtime_provenance.TRUST_INPUTS == runtime_provenance.WINDOWS_TRUST_INPUTS
    assert "validate_windows.ps1" in runtime_provenance.WINDOWS_TRUST_INPUTS
    assert "requirements-ci-runtime-windows.lock" in runtime_provenance.WINDOWS_TRUST_INPUTS
    assert "validate_linux_macos.sh" not in runtime_provenance.WINDOWS_TRUST_INPUTS
    checks += 1
    print("[GREEN] legacy Windows trust-input API remains compatible")

    posix = runtime_provenance.POSIX_TRUST_INPUTS
    assert "validate_linux_macos.sh" in posix
    assert "requirements-ci-runtime-posix.lock" in posix
    assert "release_manifest.json" in posix
    assert "runtime_provenance.py" in posix
    assert "validate_windows.ps1" not in posix
    assert "requirements-ci-runtime-windows.lock" not in posix
    assert "ensure_runtime.ps1" not in posix
    checks += 1
    print("[GREEN] POSIX receipt binds the POSIX validator and POSIX dependency lock")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _populate(root, runtime_provenance.WINDOWS_TRUST_INPUTS)
        win = runtime_provenance.build_receipt(
            root,
            python_version=runtime_provenance.REQUIRED_PYTHON,
            profile="windows",
        )
        assert set(win["inputs"]) == set(runtime_provenance.WINDOWS_TRUST_INPUTS)
        assert set(win) == {"schema", "python_version", "inputs"}
    checks += 1
    print("[GREEN] Windows receipt format and trust boundary remain unchanged")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _populate(root, runtime_provenance.POSIX_TRUST_INPUTS)
        first = runtime_provenance.build_receipt(
            root,
            python_version=runtime_provenance.REQUIRED_PYTHON,
            profile="posix",
        )
        assert set(first["inputs"]) == set(runtime_provenance.POSIX_TRUST_INPUTS)
        validator = root / "validate_linux_macos.sh"
        validator.write_bytes(b"tampered validator\n")
        second = runtime_provenance.build_receipt(
            root,
            python_version=runtime_provenance.REQUIRED_PYTHON,
            profile="posix",
        )
        assert first != second
    checks += 1
    print("[GREEN] POSIX validator changes invalidate the POSIX provenance receipt")

    assert runtime_provenance._trust_inputs_for_profile("windows") == runtime_provenance.WINDOWS_TRUST_INPUTS
    assert runtime_provenance._trust_inputs_for_profile("posix") == runtime_provenance.POSIX_TRUST_INPUTS
    try:
        runtime_provenance._trust_inputs_for_profile("other")
    except RuntimeError:
        pass
    else:
        raise AssertionError("unknown runtime provenance profile was accepted")
    checks += 1
    print("[GREEN] runtime provenance profiles fail closed outside Windows/POSIX")

    validator = (ROOT / "validate_linux_macos.sh").read_text(encoding="utf-8")
    assert '"$venv_python" runtime_provenance.py stamp' in validator
    assert validator.index("security_tail_runner.py") < validator.index("runtime_provenance.py stamp")
    assert validator.index("runtime_provenance.py stamp") < validator.index("ALL AXVEN CHECKS GREEN")
    checks += 1
    print("[GREEN] POSIX validator stamps provenance only after the complete security tail")

    source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    assert "def _runtime_profile()" in source
    assert 'system in {"Linux", "Darwin"}' in source
    assert 'return "posix"' in source
    assert "profile = _runtime_profile()" in source
    checks += 1
    print("[GREEN] CLI stamping/checking automatically selects the current platform profile")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "validate_linux_macos.sh",
        "security_sec218_posix_runtime_provenance_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest authenticates the SEC-218 implementation and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-218 leaves canonical chain identity unchanged")

    assert checks == 9, checks
    print("SEC-218 POSIX runtime provenance: 9/9 GREEN")


if __name__ == "__main__":
    main()
