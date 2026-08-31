#!/usr/bin/env python3
"""SEC-216: runtime provenance reads must stay bound to the lstat-checked file object."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


def _swap_on_open(target: Path, replacement: Path, action):
    original_open = Path.open
    swapped = False

    def guarded_open(self: Path, *args, **kwargs):
        nonlocal swapped
        mode = args[0] if args else kwargs.get("mode", "r")
        if not swapped and self == target and "r" in mode:
            os.replace(replacement, target)
            swapped = True
        return original_open(self, *args, **kwargs)

    Path.open = guarded_open
    try:
        action()
    finally:
        Path.open = original_open
    assert swapped


def _manifest_bytes(name: str, payload: bytes) -> bytes:
    return (
        json.dumps(
            {
                "files": {
                    name: {
                        "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                }
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def main() -> None:
    checks = 0

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "input.txt"
        replacement = root / "replacement.txt"
        target.write_bytes(b"trusted-input\n")
        replacement.write_bytes(b"attacker-data\n")
        assert target.stat().st_size == replacement.stat().st_size

        def read_input():
            try:
                runtime_provenance._read_trust_input(target, "input.txt")
            except RuntimeError as exc:
                assert "changed while reading" in str(exc)
            else:
                raise AssertionError("provenance trust input accepted a same-size inode swap")

        _swap_on_open(target, replacement, read_input)
    checks += 1
    print("[GREEN] trust-input inode replacement between lstat and open is rejected")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / runtime_provenance.RECEIPT_NAME
        replacement = root / "replacement-receipt.json"
        target.write_bytes(b'{"schema":2}\n')
        replacement.write_bytes(b'{"schema":3}\n')
        assert target.stat().st_size == replacement.stat().st_size

        def read_receipt():
            try:
                runtime_provenance._read_receipt(target)
            except RuntimeError as exc:
                assert "changed while reading" in str(exc)
            else:
                raise AssertionError("runtime receipt accepted a same-size inode swap")

        _swap_on_open(target, replacement, read_receipt)
    checks += 1
    print("[GREEN] receipt inode replacement between lstat and open is rejected")

    # Windows can reuse file-index identity across os.replace in ways that make a
    # filesystem-only inode-swap fixture nondeterministic. Exercise the exact
    # production descriptor-identity gate directly while keeping the real path
    # replacement coverage above for ordinary trust inputs and receipts.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        payload = b"authenticated-payload\n"
        target = root / "payload.txt"
        target.write_bytes(payload)
        (root / "release_manifest.json").write_bytes(_manifest_bytes("payload.txt", payload))

        original_same_file = runtime_provenance._same_file
        forced_mismatch = False

        def mismatch_payload_identity(before, opened):
            nonlocal forced_mismatch
            if (
                not forced_mismatch
                and before.st_size == len(payload)
                and opened.st_size == len(payload)
            ):
                forced_mismatch = True
                return False
            return original_same_file(before, opened)

        runtime_provenance._same_file = mismatch_payload_identity
        try:
            try:
                runtime_provenance._verify_manifest_payloads(root)
            except RuntimeError as exc:
                assert "changed before hashing" in str(exc)
            else:
                raise AssertionError("runtime payload accepted a descriptor identity mismatch")
        finally:
            runtime_provenance._same_file = original_same_file
        assert forced_mismatch
    checks += 1
    print("[GREEN] manifest payload descriptor identity mismatch is rejected before hashing")

    source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    assert "os.path.samestat" in source
    assert "not _same_file(metadata, opened)" in source
    assert "not _same_file(opened, after)" in source
    assert "path.read_bytes()" not in source
    assert "path.read_text(" not in source
    checks += 1
    print("[GREEN] provenance reads are descriptor-bound and avoid path-based whole-file helpers")

    runtime_provenance._verify_manifest_payloads(ROOT)
    checks += 1
    print("[GREEN] canonical manifest-authenticated runtime payload set still verifies")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "security_sec216_runtime_provenance_path_identity_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers SEC-216 implementation and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-216 leaves canonical chain identity unchanged")

    print(f"SEC-216 runtime provenance path identity: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
