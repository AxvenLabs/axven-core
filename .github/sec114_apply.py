from pathlib import Path
import hashlib
import json

p2p_path = Path("p2p.py")
source = p2p_path.read_text(encoding="utf-8")
old = '''            with self.chain._state_lock:
                active={b.hash():i for i,b in enumerate(self.chain.blocks)}
                start=0
                for h in locator:
                    if h in active:
                        start=active[h]+1
                        break
                blocks=list(
                    self.chain.blocks[
                        start:start+limit
                    ]
                )
'''
new = '''            with self.chain._state_lock:
                start=0
                for h in locator:
                    node=self.chain.index.get(h)
                    if node is None:
                        continue
                    height=node.height
                    if (
                        0 <= height < len(self.chain.blocks)
                        and self.chain.blocks[height].hash() == h
                    ):
                        start=height+1
                        break
                blocks=list(
                    self.chain.blocks[
                        start:start+limit
                    ]
                )
'''
if source.count(old) != 1:
    raise SystemExit("SEC-114 get_blocks locator anchor mismatch")
source = source.replace(old, new, 1).replace("\r\n", "\n")
p2p_path.write_text(source, encoding="utf-8", newline="\n")

spec = '''#!/usr/bin/env python3
"""SEC-114 bound public get_blocks locator work to locator size, not chain size."""

import threading
from types import SimpleNamespace

import p2p


class CountingBlock:
    hash_calls = 0

    def __init__(self, height, block_hash):
        self.height = height
        self._hash = block_hash

    def hash(self):
        type(self).hash_calls += 1
        return self._hash

    def to_dict(self):
        return {"height": self.height}


class FakeChain:
    def __init__(self, count=1024):
        self._state_lock = threading.RLock()
        self.hashes = [f"{i + 1:064x}" for i in range(count)]
        self.blocks = [
            CountingBlock(i, self.hashes[i])
            for i in range(count)
        ]
        self.index = {
            block_hash: SimpleNamespace(height=i)
            for i, block_hash in enumerate(self.hashes)
        }


def heights(reply):
    return [raw["height"] for raw in reply["blocks"]]


def main():
    assert p2p.MAX_LOCATOR_HASHES == 64
    print("[GREEN] locator request budget remains pinned at 64")

    chain = FakeChain()
    session = p2p.PeerSession(chain)

    CountingBlock.hash_calls = 0
    reply = session.handle({
        "type": "get_blocks",
        "locator": [chain.hashes[900]],
        "limit": 2,
    })
    assert heights(reply) == [901, 902]
    assert CountingBlock.hash_calls <= 1
    print("[GREEN] active locator preserves forward sync semantics")

    side_hash = "f" * 64
    chain.index[side_hash] = SimpleNamespace(height=500)
    CountingBlock.hash_calls = 0
    reply = session.handle({
        "type": "get_blocks",
        "locator": [side_hash, chain.hashes[900]],
        "limit": 2,
    })
    assert heights(reply) == [901, 902]
    assert CountingBlock.hash_calls <= 2
    print("[GREEN] side-chain locator is not mistaken for active chain")

    unknown_hash = "e" * 64
    CountingBlock.hash_calls = 0
    reply = session.handle({
        "type": "get_blocks",
        "locator": [unknown_hash],
        "limit": 2,
    })
    assert heights(reply) == [0, 1]
    assert CountingBlock.hash_calls == 0
    print("[GREEN] unknown locator does not trigger an active-chain scan")

    side_hashes = [f"{1_000_000 + i:064x}" for i in range(p2p.MAX_LOCATOR_HASHES)]
    for side in side_hashes:
        chain.index[side] = SimpleNamespace(height=500)
    CountingBlock.hash_calls = 0
    reply = session.handle({
        "type": "get_blocks",
        "locator": side_hashes,
        "limit": 1,
    })
    assert heights(reply) == [0]
    assert CountingBlock.hash_calls <= p2p.MAX_LOCATOR_HASHES
    print("[GREEN] locator lookup work is bounded by locator count")

    source = open(p2p.__file__, "r", encoding="utf-8").read()
    assert 'active={b.hash():i for i,b in enumerate(self.chain.blocks)}' not in source
    assert 'node=self.chain.index.get(h)' in source
    assert 'self.chain.blocks[height].hash() == h' in source
    print("[GREEN] full-chain hash-map construction removed from get_blocks")

    print("SEC-114 bounded get_blocks locator work: 6/6 GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = Path("security_sec114_p2p_get_blocks_locator_work_spec.py")
spec_path.write_text(spec, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py", spec_path.name):
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
