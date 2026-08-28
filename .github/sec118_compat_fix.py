#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path


def rewrite(path, old, new):
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"anchor missing: {path}")
    if text.count(old) != 1:
        raise SystemExit(f"anchor not unique: {path}")
    text = text.replace(old, new, 1)
    p.write_text(text, encoding="utf-8", newline="\n")


rewrite(
    "p2p.py",
    """            block=axven.Block.from_dict(raw_block)\n            ok,status=self.chain.add_block(block,work_gate=block_work_gate)\n""",
    """            block=axven.Block.from_dict(raw_block)\n            if block_work_gate is None:\n                ok,status=self.chain.add_block(block)\n            else:\n                ok,status=self.chain.add_block(block,work_gate=block_work_gate)\n""",
)

spec_anchor = """    outbound_session = p2p.PeerSession(axven.Blockchain(), None)\n    reply = outbound_session.handle(msg)\n    green(\n        \"internal/outbound block handling remains unthrottled\",\n        reply[\"type\"] == \"accepted\"\n        and reply[\"status\"] == \"extended\"\n        and outbound_session.chain.validate(),\n    )\n\n"""
spec_replacement = spec_anchor + """    class LegacyCompatibleChain:\n        def __init__(self):\n            self.seen = None\n        def add_block(self, block):\n            self.seen = block\n            return True, \"extended\"\n\n    legacy_chain = LegacyCompatibleChain()\n    legacy_reply = p2p.PeerSession(legacy_chain, None).handle(msg)\n    green(\n        \"unmetered session preserves legacy add_block call shape\",\n        legacy_reply[\"type\"] == \"accepted\"\n        and legacy_reply[\"status\"] == \"extended\"\n        and legacy_chain.seen is not None,\n    )\n\n"""
rewrite(
    "security_sec118_p2p_inbound_block_work_budget_spec.py",
    spec_anchor,
    spec_replacement,
)

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py", "security_sec118_p2p_inbound_block_work_budget_spec.py"):
    raw = Path(name).read_bytes().replace(b"\r\n", b"\n")
    Path(name).write_bytes(raw)
    manifest["files"][name] = {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
print("SEC-118 compatibility fix staged")
