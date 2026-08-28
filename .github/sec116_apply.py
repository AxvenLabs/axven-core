#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "axven.py"
text = path.read_text(encoding="utf-8")


def replace_block(src, start, end, replacement):
    a = src.find(start)
    if a < 0:
        raise SystemExit(f"SEC-116 start anchor not found: {start!r}")
    b = src.find(end, a)
    if b < 0:
        raise SystemExit(f"SEC-116 end anchor not found: {end!r}")
    return src[:a] + replacement + src[b:]


view_class = '''\n\nclass _IndexedBlockPath:\n    """Lazy ancestry sequence backed by active blocks plus retained side nodes."""\n    def __init__(self, active_blocks, fork_height, side_nodes):\n        self._active_blocks = active_blocks\n        self.fork_height = fork_height\n        self.side_nodes = tuple(side_nodes)\n        self._length = fork_height + 1 + len(self.side_nodes)\n\n    def __len__(self):\n        return self._length\n\n    def __getitem__(self, key):\n        if isinstance(key, slice):\n            return [self[i] for i in range(*key.indices(self._length))]\n        if type(key) is not int:\n            raise TypeError("block path index must be int or slice")\n        if key < 0:\n            key += self._length\n        if key < 0 or key >= self._length:\n            raise IndexError("block path index out of range")\n        if key <= self.fork_height:\n            return self._active_blocks[key]\n        return self.side_nodes[key - self.fork_height - 1].block\n'''
anchor = "\n\nclass Blockchain:\n"
if anchor not in text:
    raise SystemExit("SEC-116 Blockchain anchor not found")
text = text.replace(anchor, view_class + anchor, 1)

old = "        self.undo = {}\n        self.orphans = {}\n"
new = "        self.undo = {}\n        self.side_sizes = {}\n        self.orphans = {}\n"
if old not in text:
    raise SystemExit("SEC-116 side tracking init anchor not found")
text = text.replace(old, new, 1)

helpers = '''    def _is_active_index_node(self, block_hash, node):\n        height = node.height\n        return (\n            0 <= height < len(self.blocks)\n            and self.blocks[height].hash() == block_hash\n        )\n\n    def _indexed_path_view(self, node):\n        """Return exact ancestry semantics without materializing the active chain."""\n        side_rev = []\n        seen = set()\n        cur = node\n        while True:\n            block_hash = cur.block.hash()\n            if self._is_active_index_node(block_hash, cur):\n                side_rev.reverse()\n                return _IndexedBlockPath(self.blocks, cur.height, side_rev)\n            if block_hash in seen:\n                raise RuntimeError("side-chain ancestry cycle")\n            seen.add(block_hash)\n            side_rev.append(cur)\n            cur = self.index.get(cur.parent_hash)\n            if cur is None:\n                raise RuntimeError("side-chain ancestry is not indexed")\n\n'''
marker = "    def _state_for_index_node(self, node):\n"
pos = text.find(marker)
if pos < 0:
    raise SystemExit("SEC-116 state method anchor not found")
text = text[:pos] + helpers + text[pos:]

state_method = '''    def _state_for_index_node(self, node):\n        """Build an isolated validated state snapshot at an indexed node."""\n        path = self._indexed_path_view(node)\n        branch = list(path.side_nodes)\n        fork_height = path.fork_height\n\n        trial_utxo = copy.deepcopy(self.utxo)\n        trial_blocks = list(self.blocks)\n        trial_issued = self.total_issued\n\n        while len(trial_blocks) - 1 > fork_height:\n            blk = trial_blocks.pop()\n            undo = self.undo.get(blk.hash())\n            if undo is None:\n                return False, f"Missing active undo at {blk.height}", None, 0\n            _undo_forward(undo, trial_utxo)\n            trial_issued -= undo.reward\n\n        for branch_node in branch:\n            blk = branch_node.block\n            height = len(trial_blocks)\n            ok, reason, _undo, reward, _fees = _apply_forward(\n                blk, trial_utxo, height, trial_issued\n            )\n            if not ok:\n                return False, reason, None, 0\n            trial_blocks.append(blk)\n            trial_issued += reward\n\n        return True, "OK", trial_utxo, trial_issued\n\n'''
text = replace_block(
    text,
    "    def _state_for_index_node(self, node):\n",
    "    def _validate_side_block_state(self, block, parent_node, height):\n",
    state_method,
)

snapshot_method = '''    def _side_index_snapshot(self):\n        side_nodes = {}\n        side_sizes = {}\n        for block_hash, block_bytes in self.side_sizes.items():\n            node = self.index.get(block_hash)\n            if node is None:\n                raise RuntimeError("side-chain tracking/index mismatch")\n            side_nodes[block_hash] = node\n            side_sizes[block_hash] = block_bytes\n        return side_nodes, side_sizes\n\n'''
text = replace_block(
    text,
    "    def _side_index_snapshot(self):\n",
    "    def _protected_side_ancestry(self, parent_hash, active_hashes):\n",
    snapshot_method,
)

protected_method = '''    def _protected_side_ancestry(self, parent_hash):\n        protected = set()\n        current_hash = parent_hash\n        while current_hash in self.side_sizes:\n            if current_hash in protected:\n                raise RuntimeError("side-chain ancestry cycle")\n            node = self.index.get(current_hash)\n            if node is None:\n                raise RuntimeError("side-chain tracking/index mismatch")\n            protected.add(current_hash)\n            current_hash = node.parent_hash\n        return protected\n\n'''
text = replace_block(
    text,
    "    def _protected_side_ancestry(self, parent_hash, active_hashes):\n",
    "    def _prune_side_index_for_budget(self, extra_count=0, extra_bytes=0, protected=None):\n",
    protected_method,
)

prune_method = '''    def _prune_side_index_for_budget(self, extra_count=0, extra_bytes=0, protected=None):\n        protected = set(protected or ())\n        side_nodes, side_sizes = self._side_index_snapshot()\n        side_count = len(side_nodes)\n        side_bytes = sum(side_sizes.values())\n\n        def within_budget():\n            return (\n                side_count + extra_count <= MAX_SIDECHAIN_BLOCKS\n                and side_bytes + extra_bytes <= MAX_SIDECHAIN_BYTES\n            )\n\n        if within_budget():\n            return True\n\n        children = {block_hash: set() for block_hash in side_nodes}\n        for block_hash, node in side_nodes.items():\n            if node.parent_hash in children:\n                children[node.parent_hash].add(block_hash)\n\n        def leaf_key(block_hash):\n            node = side_nodes[block_hash]\n            return (node.height, block_hash)\n\n        leaves = [\n            block_hash for block_hash in side_nodes\n            if not children[block_hash] and block_hash not in protected\n        ]\n        leaves.sort(key=leaf_key)\n        removed = []\n\n        while not within_budget() and leaves:\n            block_hash = leaves.pop(0)\n            if block_hash not in side_nodes or block_hash in protected:\n                continue\n            node = side_nodes.pop(block_hash)\n            side_count -= 1\n            side_bytes -= side_sizes.pop(block_hash)\n            removed.append(block_hash)\n            parent_hash = node.parent_hash\n            if parent_hash in children:\n                children[parent_hash].discard(block_hash)\n                if (\n                    parent_hash in side_nodes\n                    and not children[parent_hash]\n                    and parent_hash not in protected\n                ):\n                    leaves.append(parent_hash)\n                    leaves.sort(key=leaf_key)\n\n        for block_hash in removed:\n            self.index.pop(block_hash, None)\n            self.side_sizes.pop(block_hash, None)\n        return within_budget()\n\n'''
text = replace_block(
    text,
    "    def _prune_side_index_for_budget(self, extra_count=0, extra_bytes=0, protected=None):\n",
    "    def balance(self, address):\n",
    prune_method,
)

old = "        path = self._ancestry(parent)\n        err = _check_context(block, path, height)\n"
new = "        path = self._indexed_path_view(parent_node)\n        err = _check_context(block, path, height)\n"
if old not in text:
    raise SystemExit("SEC-116 add-block ancestry anchor not found")
text = text.replace(old, new, 1)

old = '''            block_bytes = serialized_block_size(block)\n            active_hashes, _side_nodes, side_sizes = self._side_index_snapshot()\n            protected = self._protected_side_ancestry(parent, active_hashes)\n            protected_bytes = sum(side_sizes[h] for h in protected)\n'''
new = '''            block_bytes = serialized_block_size(block)\n            _side_nodes, side_sizes = self._side_index_snapshot()\n            protected = self._protected_side_ancestry(parent)\n            protected_bytes = sum(side_sizes[h] for h in protected)\n'''
if old not in text:
    raise SystemExit("SEC-116 side admission snapshot anchor not found")
text = text.replace(old, new, 1)

old = '''        else:\n            status = "side-chain"\n        self._connect_orphans(h)\n'''
new = '''        else:\n            self.side_sizes[h] = block_bytes\n            status = "side-chain"\n        self._connect_orphans(h)\n'''
if old not in text:
    raise SystemExit("SEC-116 side publication anchor not found")
text = text.replace(old, new, 1)

reorg_method = '''    def _reorg_to(self, node):\n        tu = copy.deepcopy(self.utxo)\n        tblocks = list(self.blocks)\n        tissued, tcw = self.total_issued, self.chainwork\n        tundo = dict(self.undo)\n        path = self._indexed_path_view(node)\n        branch = list(path.side_nodes)\n        fork_height = path.fork_height\n        disconnected = []\n        while len(tblocks) - 1 > fork_height:\n            blk = tblocks[-1]\n            undo = tundo.pop(blk.hash())\n            _undo_forward(undo, tu)\n            tissued -= undo.reward\n            tcw -= work_of(blk.target)\n            tblocks.pop()\n            disconnected.append(blk)\n        for bn in branch:\n            blk = bn.block\n            hh = len(tblocks)\n            ok, reason, undo, reward, _fees = _apply_forward(blk, tu, hh, tissued)\n            if not ok:\n                return False, reason\n            tblocks.append(blk)\n            tundo[blk.hash()] = undo\n            tissued += reward\n            tcw += work_of(blk.target)\n\n        new_side_sizes = dict(self.side_sizes)\n        for bn in branch:\n            new_side_sizes.pop(bn.block.hash(), None)\n        for blk in disconnected:\n            new_side_sizes[blk.hash()] = serialized_block_size(blk)\n\n        self.utxo, self.blocks = tu, tblocks\n        self.total_issued, self.chainwork, self.undo = tissued, tcw, tundo\n        self.side_sizes = new_side_sizes\n        self._reevaluate_mempool(disconnected)\n        return True, "OK"\n\n'''
text = replace_block(
    text,
    "    def _reorg_to(self, node):\n",
    "    def _reevaluate_mempool(self, disconnected=None):\n",
    reorg_method,
)

path.write_text(text, encoding="utf-8", newline="\n")

spec = r'''#!/usr/bin/env python3
"""SEC-116 bounds side-fork active-chain traversal without changing context rules."""

import copy

import axven


def make_sibling(chain, wallet):
    tip = chain.tip
    height = tip.height
    assert height >= 2 and height % axven.ADJUST_INTERVAL != 0
    parent_hash = tip.previous_hash

    trial = copy.deepcopy(chain.utxo)
    tip_undo = chain.undo[tip.hash()]
    axven._undo_forward(tip_undo, trial)
    issued = chain.total_issued - tip_undo.reward

    coinbase = axven.make_coinbase(
        wallet.address,
        axven.block_reward(height, issued),
        height,
    )
    block = axven.Block(
        height=height,
        timestamp=tip.timestamp,
        previous_hash=parent_hash,
        merkle_root=axven.merkle_root([coinbase.txid()]),
        target=tip.target,
        transactions=[coinbase.to_dict()],
        nonce=0,
        miner=wallet.address,
        utxo_state_root="",
    )
    ok, reason, _undo, _reward, _fees = axven._transition(
        block, trial, height, issued
    )
    assert ok, reason
    block.utxo_state_root = axven.expected_state_root(trial, height)
    while not block.pow_ok():
        block.nonce += 1
    assert axven._check_context(block, chain.blocks[:height], height) is None
    return block


def main():
    checks = 0
    miner = axven.Wallet()
    chain = axven.Blockchain()
    for _ in range(32):
        chain.mine(miner.address)

    parent_hash = chain.tip.previous_hash
    parent_node = chain.index[parent_hash]
    view = chain._indexed_path_view(parent_node)
    legacy = chain._ancestry(parent_hash)
    assert len(view) == len(legacy)
    assert [b.hash() for b in view] == [b.hash() for b in legacy]
    checks += 1
    print("[GREEN] indexed active path preserves exact ancestry sequence")

    sibling = make_sibling(chain, axven.Wallet())
    side_hash = sibling.hash()
    checks += 1
    print("[GREEN] alternate near-tip block is context-valid before admission")

    historical = list(chain.blocks[:-16])
    try:
        def ancestry_forbidden(_):
            raise AssertionError("full ancestry materialization attempted")
        chain._ancestry = ancestry_forbidden

        for block in historical:
            height = block.height
            def forbidden_hash(height=height):
                raise AssertionError(
                    f"historical active hash scan attempted at height {height}"
                )
            block.hash = forbidden_hash

        ok, status = chain.add_block(sibling)
        assert ok and status == "side-chain", (ok, status)
    finally:
        if "_ancestry" in chain.__dict__:
            del chain.__dict__["_ancestry"]
        for block in historical:
            if "hash" in block.__dict__:
                del block.__dict__["hash"]
    checks += 1
    print("[GREEN] side admission avoids full ancestry and active hash scans")

    side_node = chain.index[side_hash]
    side_view = chain._indexed_path_view(side_node)
    side_legacy = chain._ancestry(side_hash)
    assert [b.hash() for b in side_view] == [b.hash() for b in side_legacy]
    checks += 1
    print("[GREEN] indexed side path preserves exact legacy ancestry sequence")

    side_nodes, side_sizes = chain._side_index_snapshot()
    assert set(side_nodes) == {side_hash}
    assert side_sizes == {side_hash: axven.serialized_block_size(sibling)}
    checks += 1
    print("[GREEN] retained side-node byte tracking is exact and bounded")

    assert chain.validate()
    checks += 1
    print("[GREEN] active chain remains consensus-valid after bounded side admission")

    source = open(axven.__file__, "r", encoding="utf-8").read()
    assert "path = self._indexed_path_view(parent_node)" in source
    assert "err = _check_context(block, path, height)" in source
    assert "active_hashes = {b.hash() for b in self.blocks}" not in source
    assert "self.side_sizes" in source
    checks += 1
    print("[GREEN] production wiring removes full-chain side-fork scans")

    assert checks == 7
    print("SEC-116 bounded side-fork path work: 7/7 GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = ROOT / "security_sec116_sidefork_path_work_spec.py"
spec_path.write_text(spec, encoding="utf-8", newline="\n")

manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("axven.py", spec_path.name):
    file_path = ROOT / name
    data = file_path.read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
