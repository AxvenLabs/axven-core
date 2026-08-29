#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

source = Path("axven.py")
text = source.read_text(encoding="utf-8")

if "def _preflight_chain_state_json(" in text:
    print("SEC-150 source already built")
    raise SystemExit(0)

marker = "\n\nclass StateStore:\n"
if marker not in text:
    raise SystemExit("StateStore marker not found")

helpers = r'''

MAX_CHAIN_STATE_JSON_NESTING_DEPTH = 32


def _preflight_chain_state_json(raw, max_depth=MAX_CHAIN_STATE_JSON_NESTING_DEPTH):
    """Reject pathological persisted-chain nesting before json.loads recursion."""
    if type(raw) is not bytes:
        raise ValueError("invalid chain state JSON bytes")
    if type(max_depth) is not int or max_depth <= 0:
        raise ValueError("invalid chain state JSON depth limit")

    stack = []
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
            continue
        if byte in (0x7B, 0x5B):
            stack.append(byte)
            if len(stack) > max_depth:
                raise ValueError("chain state JSON nesting depth exceeded")
            continue
        if byte in (0x7D, 0x5D):
            expected = 0x7B if byte == 0x7D else 0x5B
            if stack and stack[-1] == expected:
                stack.pop()


def _reject_duplicate_chain_state_json_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate chain state JSON key: {key}")
        obj[key] = value
    return obj
'''
text = text.replace(marker, helpers + marker, 1)

old_load = '''    def load(self) -> Blockchain:
        payload = json.loads(self.path.read_text())
        if payload.get("chain_id") != CHAIN_ID:
            raise ValueError("chain_id mismatch")
        if payload.get("config_fingerprint") != CONFIG_FINGERPRINT:
            raise ValueError("config fingerprint mismatch")
        blocks = [Block.from_dict(b) for b in payload.get("blocks", [])]
        if not blocks or blocks[0].hash() != _genesis().hash():
            raise ValueError("Bad genesis identity")
        bc = Blockchain()
        for blk in blocks[1:]:
            ok, reason = bc.add_block(blk)
            if not ok:
                raise ValueError(f"load failed: {reason}")
        bc.mempool = None  # v1 ground truth: mempool is deliberately in-memory only.
        return bc
'''
new_load = '''    def load(self) -> Blockchain:
        raw = self.path.read_bytes()
        _preflight_chain_state_json(raw)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeError as exc:
            raise ValueError("invalid chain state JSON encoding") from exc
        try:
            payload = json.loads(
                decoded,
                object_pairs_hook=_reject_duplicate_chain_state_json_keys,
            )
        except json.JSONDecodeError as exc:
            raise ValueError("invalid chain state JSON") from exc
        except RecursionError as exc:
            raise ValueError("invalid chain state JSON") from exc
        if type(payload) is not dict:
            raise ValueError("chain state must be an object")
        if payload.get("chain_id") != CHAIN_ID:
            raise ValueError("chain_id mismatch")
        if payload.get("config_fingerprint") != CONFIG_FINGERPRINT:
            raise ValueError("config fingerprint mismatch")
        blocks = [Block.from_dict(b) for b in payload.get("blocks", [])]
        if not blocks or blocks[0].hash() != _genesis().hash():
            raise ValueError("Bad genesis identity")
        bc = Blockchain()
        for blk in blocks[1:]:
            ok, reason = bc.add_block(blk)
            if not ok:
                raise ValueError(f"load failed: {reason}")
        bc.mempool = None  # v1 ground truth: mempool is deliberately in-memory only.
        return bc
'''
if old_load not in text:
    raise SystemExit("StateStore.load contract changed unexpectedly")
text = text.replace(old_load, new_load, 1)
source.write_text(text, encoding="utf-8", newline="\n")

spec_name = "security_sec150_chain_state_json_preparse_spec.py"
spec = r'''#!/usr/bin/env python3
"""SEC-150 persisted chain-state JSON preparse hardening contract."""

import tempfile
import axven


def _expect_value_error(label, fn, contains=None):
    try:
        fn()
    except ValueError as exc:
        if contains is not None:
            assert contains in str(exc), (label, str(exc))
        print(f"[GREEN] {label}")
        return 1
    raise AssertionError(f"{label}: expected ValueError")


def main():
    checks = 0
    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        chain = axven.Blockchain()
        store.persist(chain)
        loaded = store.load()
        assert loaded.tip.hash() == chain.tip.hash()
        assert loaded.chainwork == chain.chainwork
        checks += 1
        print("[GREEN] canonical chain-state roundtrip preserved")

    limit = axven.MAX_CHAIN_STATE_JSON_NESTING_DEPTH
    boundary = ("[" * limit + "0" + "]" * limit).encode("ascii")
    axven._preflight_chain_state_json(boundary)
    checks += 1
    print("[GREEN] exact chain-state nesting boundary accepted")

    checks += _expect_value_error(
        "over-depth chain-state JSON rejected before parsing",
        lambda: axven._preflight_chain_state_json(
            ("[" * (limit + 1) + "0" + "]" * (limit + 1)).encode("ascii")
        ),
        "nesting depth exceeded",
    )

    quoted = b'{"text":"[[[[{{{{\\\"still-string\\\"}}}}]]]]"}'
    axven._preflight_chain_state_json(quoted)
    checks += 1
    print("[GREEN] quote-aware preflight ignores structural bytes in strings")

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        raw = (
            '{"chain_id":"%s","chain_id":"%s",'
            '"config_fingerprint":"%s","blocks":[]}'
            % (axven.CHAIN_ID, axven.CHAIN_ID, axven.CONFIG_FINGERPRINT)
        ).encode("utf-8")
        store.path.write_bytes(raw)
        checks += _expect_value_error(
            "duplicate top-level chain-state key rejected",
            store.load,
            "duplicate chain state JSON key",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        raw = (
            '{"chain_id":"%s","config_fingerprint":"%s",'
            '"blocks":[{"height":0,"height":0}]}'
            % (axven.CHAIN_ID, axven.CONFIG_FINGERPRINT)
        ).encode("utf-8")
        store.path.write_bytes(raw)
        checks += _expect_value_error(
            "duplicate nested chain-state key rejected recursively",
            store.load,
            "duplicate chain state JSON key",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        store.path.write_bytes(b'{"chain_id":"' + b'\xff' + b'"}')
        checks += _expect_value_error(
            "invalid UTF-8 chain-state encoding fails closed",
            store.load,
            "encoding",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        store.path.write_bytes(b'{"chain_id":')
        checks += _expect_value_error(
            "malformed chain-state JSON fails closed",
            store.load,
            "invalid chain state JSON",
        )

    with tempfile.TemporaryDirectory() as td:
        store = axven.StateStore(td)
        store.path.write_bytes(b'[]')
        checks += _expect_value_error(
            "non-object chain-state envelope rejected",
            store.load,
            "chain state must be an object",
        )

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 10, checks
    print("SEC-150 chain-state JSON preparse: 10/10 GREEN")


if __name__ == "__main__":
    main()
'''
Path(spec_name).write_text(spec, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("axven.py", spec_name):
    data = Path(name).read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
print("SEC-150 source/spec/manifest generated")
