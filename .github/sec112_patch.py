from pathlib import Path
import hashlib
import json
import re

source_path = Path("axven.py")
source = source_path.read_text(encoding="utf-8")

constant_anchor = "MAX_ORPHAN_BYTES = 64 * 1024 * 1024\n"
if source.count(constant_anchor) != 1:
    raise SystemExit("SEC-112 constant anchor mismatch")
source = source.replace(
    constant_anchor,
    constant_anchor
    + "MAX_SIDECHAIN_BLOCKS = 64\n"
    + "MAX_SIDECHAIN_BYTES = 64 * 1024 * 1024\n",
    1,
)

helper_anchor = "        return ok, reason\n\n    def balance(self, address):\n"
if source.count(helper_anchor) != 1:
    raise SystemExit("SEC-112 helper anchor mismatch")
helper_lines = [
    "        return ok, reason",
    "",
    "    def _side_index_snapshot(self):",
    "        active_hashes = {b.hash() for b in self.blocks}",
    "        side_nodes = {",
    "            block_hash: node",
    "            for block_hash, node in self.index.items()",
    "            if block_hash not in active_hashes",
    "        }",
    "        side_sizes = {",
    "            block_hash: serialized_block_size(node.block)",
    "            for block_hash, node in side_nodes.items()",
    "        }",
    "        return active_hashes, side_nodes, side_sizes",
    "",
    "    def _protected_side_ancestry(self, parent_hash, active_hashes):",
    "        protected = set()",
    "        current_hash = parent_hash",
    "        while current_hash in self.index and current_hash not in active_hashes:",
    "            if current_hash in protected:",
    "                raise RuntimeError(\"side-chain ancestry cycle\")",
    "            protected.add(current_hash)",
    "            current_hash = self.index[current_hash].parent_hash",
    "        return protected",
    "",
    "    def _prune_side_index_for_budget(self, extra_count=0, extra_bytes=0, protected=None):",
    "        protected = set(protected or ())",
    "        _active_hashes, side_nodes, side_sizes = self._side_index_snapshot()",
    "        side_count = len(side_nodes)",
    "        side_bytes = sum(side_sizes.values())",
    "",
    "        def within_budget():",
    "            return (",
    "                side_count + extra_count <= MAX_SIDECHAIN_BLOCKS",
    "                and side_bytes + extra_bytes <= MAX_SIDECHAIN_BYTES",
    "            )",
    "",
    "        if within_budget():",
    "            return True",
    "",
    "        children = {block_hash: set() for block_hash in side_nodes}",
    "        for block_hash, node in side_nodes.items():",
    "            if node.parent_hash in children:",
    "                children[node.parent_hash].add(block_hash)",
    "",
    "        def leaf_key(block_hash):",
    "            node = side_nodes[block_hash]",
    "            return (node.height, block_hash)",
    "",
    "        leaves = [",
    "            block_hash for block_hash in side_nodes",
    "            if not children[block_hash] and block_hash not in protected",
    "        ]",
    "        leaves.sort(key=leaf_key)",
    "        removed = []",
    "",
    "        while not within_budget() and leaves:",
    "            block_hash = leaves.pop(0)",
    "            if block_hash not in side_nodes or block_hash in protected:",
    "                continue",
    "            node = side_nodes.pop(block_hash)",
    "            side_count -= 1",
    "            side_bytes -= side_sizes.pop(block_hash)",
    "            removed.append(block_hash)",
    "            parent_hash = node.parent_hash",
    "            if parent_hash in children:",
    "                children[parent_hash].discard(block_hash)",
    "                if (",
    "                    parent_hash in side_nodes",
    "                    and not children[parent_hash]",
    "                    and parent_hash not in protected",
    "                ):",
    "                    leaves.append(parent_hash)",
    "                    leaves.sort(key=leaf_key)",
    "",
    "        for block_hash in removed:",
    "            self.index.pop(block_hash, None)",
    "        return within_budget()",
    "",
    "    def balance(self, address):",
]
source = source.replace(helper_anchor, "\n".join(helper_lines) + "\n", 1)

admission_pattern = re.compile(
    r"^        if parent != self\.tip\.hash\(\) and cw <= self\.chainwork:\n"
    r"            ok, reason = self\._validate_side_block_state\(\n"
    r"                block, parent_node, height\n"
    r"            \)\n"
    r"            if not ok:\n"
    r"                return False, reason\n"
    r"\n"
    r"        node = BlockNode\(block, height, cw, parent\)\n",
    re.MULTILINE,
)
admission_lines = [
    "        is_nonwinning_side = parent != self.tip.hash() and cw <= self.chainwork",
    "        if is_nonwinning_side:",
    "            ok, reason = self._validate_side_block_state(",
    "                block, parent_node, height",
    "            )",
    "            if not ok:",
    "                return False, reason",
    "",
    "            block_bytes = serialized_block_size(block)",
    "            active_hashes, _side_nodes, side_sizes = self._side_index_snapshot()",
    "            protected = self._protected_side_ancestry(parent, active_hashes)",
    "            protected_bytes = sum(side_sizes[h] for h in protected)",
    "            if (",
    "                len(protected) + 1 > MAX_SIDECHAIN_BLOCKS",
    "                or protected_bytes + block_bytes > MAX_SIDECHAIN_BYTES",
    "            ):",
    "                return False, \"side-chain retention budget exceeded\"",
    "            if not self._prune_side_index_for_budget(",
    "                extra_count=1,",
    "                extra_bytes=block_bytes,",
    "                protected=protected,",
    "            ):",
    "                return False, \"side-chain retention budget full\"",
    "",
    "        node = BlockNode(block, height, cw, parent)",
]
source, count = admission_pattern.subn("\n".join(admission_lines) + "\n", source, count=1)
if count != 1:
    raise SystemExit(f"SEC-112 side admission anchor mismatch: {count}")

reorg_anchor = (
    "            status = \"reorg\"\n"
    "        else:\n"
    "            status = \"side-chain\"\n"
)
if source.count(reorg_anchor) != 1:
    raise SystemExit("SEC-112 reorg anchor mismatch")
source = source.replace(
    reorg_anchor,
    "            self._prune_side_index_for_budget()\n" + reorg_anchor,
    1,
)
source_path.write_text(source, encoding="utf-8")

spec_name = "security_sec112_sidechain_retention_bounds_spec.py"
spec = '''#!/usr/bin/env python3
"""SEC-112 bounded side-chain retention against public fork-flood memory growth."""

import axven


def side_usage(chain):
    active_hashes = {block.hash() for block in chain.blocks}
    side_nodes = {
        block_hash: node
        for block_hash, node in chain.index.items()
        if block_hash not in active_hashes
    }
    side_bytes = sum(
        axven.serialized_block_size(node.block)
        for node in side_nodes.values()
    )
    return active_hashes, side_nodes, side_bytes


def mine_chain(count):
    chain = axven.Blockchain()
    wallet = axven.Wallet()
    for _ in range(count):
        chain.mine(wallet.address)
    return chain


def main():
    assert axven.MAX_SIDECHAIN_BLOCKS == 64
    assert axven.MAX_SIDECHAIN_BYTES == 64 * 1024 * 1024
    print("[GREEN] side-chain count and byte budgets pinned")

    old_count = axven.MAX_SIDECHAIN_BLOCKS
    old_bytes = axven.MAX_SIDECHAIN_BYTES
    try:
        axven.MAX_SIDECHAIN_BLOCKS = 2
        axven.MAX_SIDECHAIN_BYTES = 64 * 1024 * 1024

        active = mine_chain(5)
        fork_a = mine_chain(3)
        fork_b = mine_chain(1)
        active_hashes = {block.hash() for block in active.blocks}

        ok, status = active.add_block(fork_a.blocks[1])
        assert ok and status == "side-chain"
        ok, status = active.add_block(fork_a.blocks[2])
        assert ok and status == "side-chain"
        _active, side_nodes, _bytes = side_usage(active)
        assert len(side_nodes) == 2
        print("[GREEN] valid forks retained up to count budget")

        ok, status = active.add_block(fork_b.blocks[1])
        assert ok and status == "side-chain"
        current_active, side_nodes, side_bytes = side_usage(active)
        assert len(side_nodes) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side_bytes <= axven.MAX_SIDECHAIN_BYTES
        assert fork_b.blocks[1].hash() in side_nodes
        assert active_hashes <= set(active.index)
        assert current_active == active_hashes
        print("[GREEN] unrelated side leaves pruned without touching active chain")

        ok, status = active.add_block(fork_a.blocks[2])
        assert ok and status == "side-chain"
        _active, side_nodes, side_bytes = side_usage(active)
        assert fork_a.blocks[1].hash() in side_nodes
        assert fork_a.blocks[2].hash() in side_nodes
        assert fork_b.blocks[1].hash() not in active.index
        assert len(side_nodes) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side_bytes <= axven.MAX_SIDECHAIN_BYTES
        print("[GREEN] protected incoming fork ancestry survives pruning")

        active2 = mine_chain(2)
        fork2 = mine_chain(3)
        ok, status = active2.add_block(fork2.blocks[1])
        assert ok and status == "side-chain"
        ok, status = active2.add_block(fork2.blocks[2])
        assert ok and status == "side-chain"
        ok, status = active2.add_block(fork2.blocks[3])
        assert ok and status == "reorg"
        assert active2.tip.hash() == fork2.tip.hash()
        assert active2.validate()
        active2_hashes, side2, side2_bytes = side_usage(active2)
        assert active2_hashes <= set(active2.index)
        assert len(side2) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side2_bytes <= axven.MAX_SIDECHAIN_BYTES
        print("[GREEN] heavier valid fork still reorgs")

        active3 = mine_chain(3)
        fork3 = mine_chain(2)
        first_size = axven.serialized_block_size(fork3.blocks[1])
        second_size = axven.serialized_block_size(fork3.blocks[2])
        axven.MAX_SIDECHAIN_BLOCKS = 64
        axven.MAX_SIDECHAIN_BYTES = first_size + second_size - 1
        ok, status = active3.add_block(fork3.blocks[1])
        assert ok and status == "side-chain"
        before_index = set(active3.index)
        ok, reason = active3.add_block(fork3.blocks[2])
        assert not ok and "retention budget" in reason
        assert set(active3.index) == before_index
        _active, side3, side3_bytes = side_usage(active3)
        assert len(side3) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side3_bytes <= axven.MAX_SIDECHAIN_BYTES
        print("[GREEN] protected fork cannot exceed byte budget")
    finally:
        axven.MAX_SIDECHAIN_BLOCKS = old_count
        axven.MAX_SIDECHAIN_BYTES = old_bytes

    source_text = open(axven.__file__, "r", encoding="utf-8").read()
    assert "_prune_side_index_for_budget" in source_text
    assert "protected=protected" in source_text
    print("[GREEN] bounded retention wired before side index publish")
    print("SEC-112 bounded side-chain retention: 6/6 GREEN")


if __name__ == "__main__":
    main()
'''
Path(spec_name).write_text(spec, encoding="utf-8")

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
)
