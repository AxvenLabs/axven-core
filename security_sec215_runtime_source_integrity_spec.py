#!/usr/bin/env python3
"""SEC-215: validated-runtime receipts must bind manifest payload contents."""
from __future__ import annotations

import hashlib
import json
import platform
import tempfile
from pathlib import Path

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


def _manifest_bytes(payload_name: str, payload: bytes) -> bytes:
    return (
        json.dumps(
            {
                "files": {
                    payload_name: {
                        "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                }
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _fake_runtime_root(root: Path, payload: bytes = b"trusted runtime payload\n") -> Path:
    for index, name in enumerate(runtime_provenance.TRUST_INPUTS):
        if name == "release_manifest.json":
            continue
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"trusted-input-{index}\n".encode("utf-8"))
    payload_path = root / "payload.txt"
    payload_path.write_bytes(payload)
    (root / "release_manifest.json").write_bytes(_manifest_bytes("payload.txt", payload))
    (root / ".venv").mkdir(parents=True, exist_ok=True)
    return payload_path


def main() -> None:
    checks = 0

    # Canonical checked-out payload set must match its manifest exactly.
    runtime_provenance._verify_manifest_payloads(ROOT)
    checks += 1
    print("[GREEN] canonical runtime source tree matches the authenticated release manifest")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        payload = _fake_runtime_root(root)
        runtime_provenance._verify_manifest_payloads(root)
        original = payload.read_bytes()
        payload.write_bytes(b"X" * len(original))
        try:
            runtime_provenance._verify_manifest_payloads(root)
        except RuntimeError as exc:
            assert "hash mismatch" in str(exc)
        else:
            raise AssertionError("runtime provenance accepted post-validation source tampering")
    checks += 1
    print("[GREEN] same-size source tampering is rejected by manifest payload hashing")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        payload = _fake_runtime_root(root)
        receipt = runtime_provenance.build_receipt(
            root, python_version=runtime_provenance.REQUIRED_PYTHON
        )
        receipt_path = runtime_provenance.receipt_path(root)
        receipt_path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        data = payload.read_bytes()
        payload.write_bytes(bytes([data[0] ^ 1]) + data[1:])

        original_assert = runtime_provenance._assert_expected_interpreter
        original_version = platform.python_version
        runtime_provenance._assert_expected_interpreter = lambda _root=root: None
        platform.python_version = lambda: runtime_provenance.REQUIRED_PYTHON
        try:
            try:
                runtime_provenance.check(root)
            except RuntimeError as exc:
                assert "release payload hash mismatch" in str(exc)
            else:
                raise AssertionError("a valid old receipt bypassed source-integrity verification")
        finally:
            runtime_provenance._assert_expected_interpreter = original_assert
            platform.python_version = original_version
    checks += 1
    print("[GREEN] a previously valid receipt cannot bless source files changed after stamping")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        payload = _fake_runtime_root(root)
        original_read_bytes = Path.read_bytes

        def guarded_read_bytes(self: Path) -> bytes:
            if self.name != "release_manifest.json":
                raise AssertionError(f"whole-file payload read used: {self}")
            return original_read_bytes(self)

        Path.read_bytes = guarded_read_bytes
        try:
            runtime_provenance._verify_manifest_payloads(root)
        finally:
            Path.read_bytes = original_read_bytes
        assert payload.exists()
    checks += 1
    print("[GREEN] runtime payload integrity uses bounded streaming instead of whole-file reads")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        outside = root.parent / "sec215-outside.txt"
        outside_bytes = b"outside\n"
        outside.write_bytes(outside_bytes)
        try:
            (root / "release_manifest.json").write_bytes(
                (
                    json.dumps(
                        {
                            "files": {
                                "../sec215-outside.txt": {
                                    "bytes": len(outside_bytes),
                                    "sha256": hashlib.sha256(outside_bytes).hexdigest(),
                                }
                            }
                        }
                    )
                    + "\n"
                ).encode("utf-8")
            )
            try:
                runtime_provenance._verify_manifest_payloads(root)
            except RuntimeError as exc:
                assert "invalid release manifest entry" in str(exc)
            else:
                raise AssertionError("runtime manifest verification accepted path traversal")
        finally:
            try:
                outside.unlink()
            except FileNotFoundError:
                pass
    checks += 1
    print("[GREEN] runtime manifest payload verification rejects path traversal")

    source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    stamp_body = source[source.index("def stamp("):source.index("def check(")]
    check_body = source[source.index("def check("):source.index("def main(")]
    assert "_verify_manifest_payloads(root)" in stamp_body
    assert "_verify_manifest_payloads(root)" in check_body
    assert "HASH_CHUNK_BYTES" in source
    assert "MAX_RELEASE_TOTAL_BYTES" in source
    checks += 1
    print("[GREEN] both receipt stamping and checking are gated by bounded payload integrity")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "security_sec215_runtime_source_integrity_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers the SEC-215 runtime-integrity gate and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-215 leaves canonical chain identity unchanged")

    assert checks == 8, checks
    print("SEC-215 runtime source integrity: 8/8 GREEN")


if __name__ == "__main__":
    main()
