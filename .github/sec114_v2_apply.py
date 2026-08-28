from pathlib import Path
from types import SimpleNamespace
import hashlib
import json

# Production: replace O(chain length) active-map construction with O(locator) index lookups.
p2p_path = Path("p2p.py")
p2p_source = p2p_path.read_text(encoding="utf-8")
old_p2p = '''            with self.chain._state_lock:\n                active={b.hash():i for i,b in enumerate(self.chain.blocks)}\n                start=0\n                for h in locator:\n                    if h in active:\n                        start=active[h]+1\n                        break\n                blocks=list(\n                    self.chain.blocks[\n                        start:start+limit\n                    ]\n                )\n'''
new_p2p = '''            with self.chain._state_lock:\n                start=0\n                for h in locator:\n                    node=self.chain.index.get(h)\n                    if node is None:\n                        continue\n                    height=node.height\n                    if (\n                        0 <= height < len(self.chain.blocks)\n                        and self.chain.blocks[height].hash() == h\n                    ):\n                        start=height+1\n                        break\n                blocks=list(\n                    self.chain.blocks[\n                        start:start+limit\n                    ]\n                )\n'''
if p2p_source.count(old_p2p) != 1:
    raise SystemExit("SEC-114 get_blocks locator anchor mismatch")
p2p_source = p2p_source.replace(old_p2p, new_p2p, 1).replace("\r\n", "\n")
p2p_path.write_text(p2p_source, encoding="utf-8", newline="\n")

# Compatibility: SEC-063's FakeChain must model the production chain.index contract.
sec063_path = Path("security_sec063_p2p_sync_response_budget_spec.py")
sec063 = sec063_path.read_text(encoding="utf-8")
old_import = "import json\nimport threading\n\nimport p2p\n"
new_import = "import json\nimport threading\nfrom types import SimpleNamespace\n\nimport p2p\n"
if sec063.count(old_import) != 1:
    raise SystemExit("SEC-114 SEC-063 import anchor mismatch")
sec063 = sec063.replace(old_import, new_import, 1)
old_fake = '''class FakeChain:\n    def __init__(self, blocks):\n        self.blocks = list(blocks)\n        self._state_lock = threading.RLock()\n'''
new_fake = '''class FakeChain:\n    def __init__(self, blocks):\n        self.blocks = list(blocks)\n        self.index = {\n            block.hash(): SimpleNamespace(height=i)\n            for i, block in enumerate(self.blocks)\n        }\n        self._state_lock = threading.RLock()\n'''
if sec063.count(old_fake) != 1:
    raise SystemExit("SEC-114 SEC-063 FakeChain anchor mismatch")
sec063 = sec063.replace(old_fake, new_fake, 1).replace("\r\n", "\n")
sec063_path.write_text(sec063, encoding="utf-8", newline="\n")

# New deterministic security contract.
spec = '''#!/usr/bin/env python3\n"""SEC-114 bound public get_blocks locator work to locator size, not chain size."""\n\nimport threading\nfrom types import SimpleNamespace\n\nimport p2p\n\n\nclass CountingBlock:\n    hash_calls = 0\n\n    def __init__(self, height, block_hash):\n        self.height = height\n        self._hash = block_hash\n\n    def hash(self):\n        type(self).hash_calls += 1\n        return self._hash\n\n    def to_dict(self):\n        return {"height": self.height}\n\n\nclass FakeChain:\n    def __init__(self, count=1024):\n        self._state_lock = threading.RLock()\n        self.hashes = [f"{i + 1:064x}" for i in range(count)]\n        self.blocks = [\n            CountingBlock(i, self.hashes[i])\n            for i in range(count)\n        ]\n        self.index = {\n            block_hash: SimpleNamespace(height=i)\n            for i, block_hash in enumerate(self.hashes)\n        }\n\n\ndef heights(reply):\n    return [raw["height"] for raw in reply["blocks"]]\n\n\ndef main():\n    assert p2p.MAX_LOCATOR_HASHES == 64\n    print("[GREEN] locator request budget remains pinned at 64")\n\n    chain = FakeChain()\n    session = p2p.PeerSession(chain)\n\n    CountingBlock.hash_calls = 0\n    reply = session.handle({\n        "type": "get_blocks",\n        "locator": [chain.hashes[900]],\n        "limit": 2,\n    })\n    assert heights(reply) == [901, 902]\n    assert CountingBlock.hash_calls <= 1\n    print("[GREEN] active locator preserves forward sync semantics")\n\n    side_hash = "f" * 64\n    chain.index[side_hash] = SimpleNamespace(height=500)\n    CountingBlock.hash_calls = 0\n    reply = session.handle({\n        "type": "get_blocks",\n        "locator": [side_hash, chain.hashes[900]],\n        "limit": 2,\n    })\n    assert heights(reply) == [901, 902]\n    assert CountingBlock.hash_calls <= 2\n    print("[GREEN] side-chain locator is not mistaken for active chain")\n\n    unknown_hash = "e" * 64\n    CountingBlock.hash_calls = 0\n    reply = session.handle({\n        "type": "get_blocks",\n        "locator": [unknown_hash],\n        "limit": 2,\n    })\n    assert heights(reply) == [0, 1]\n    assert CountingBlock.hash_calls == 0\n    print("[GREEN] unknown locator does not trigger an active-chain scan")\n\n    side_hashes = [f"{1_000_000 + i:064x}" for i in range(p2p.MAX_LOCATOR_HASHES)]\n    for side in side_hashes:\n        chain.index[side] = SimpleNamespace(height=500)\n    CountingBlock.hash_calls = 0\n    reply = session.handle({\n        "type": "get_blocks",\n        "locator": side_hashes,\n        "limit": 1,\n    })\n    assert heights(reply) == [0]\n    assert CountingBlock.hash_calls <= p2p.MAX_LOCATOR_HASHES\n    print("[GREEN] locator lookup work is bounded by locator count")\n\n    source = open(p2p.__file__, "r", encoding="utf-8").read()\n    assert 'active={b.hash():i for i,b in enumerate(self.chain.blocks)}' not in source\n    assert 'node=self.chain.index.get(h)' in source\n    assert 'self.chain.blocks[height].hash() == h' in source\n    print("[GREEN] full-chain hash-map construction removed from get_blocks")\n\n    print("SEC-114 bounded get_blocks locator work: 6/6 GREEN")\n\n\nif __name__ == "__main__":\n    main()\n'''
spec_path = Path("security_sec114_p2p_get_blocks_locator_work_spec.py")
spec_path.write_text(spec, encoding="utf-8", newline="\n")

# Refresh manifest from normalized repository bytes.
manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in (
    "p2p.py",
    "security_sec063_p2p_sync_response_budget_spec.py",
    "security_sec114_p2p_get_blocks_locator_work_spec.py",
):
    path = Path(name)
    data = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(data)
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
