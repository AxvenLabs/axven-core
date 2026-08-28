#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

path = Path("axven.py")
source = path.read_text(encoding="utf-8")

anchor = '''    def _ancestry(self, h):
        out = []
        while h in self.index:
            node = self.index[h]
            out.append(node.block)
            if node.height == 0:
                break
            h = node.parent_hash
        out.reverse()
        return out

    def balance(self, address):
'''
replacement = '''    def _ancestry(self, h):
        out = []
        while h in self.index:
            node = self.index[h]
            out.append(node.block)
            if node.height == 0:
                break
            h = node.parent_hash
        out.reverse()
        return out

    def _state_for_index_node(self, node):
        """Build an isolated validated state snapshot at an indexed node."""
        active_hashes = {b.hash() for b in self.blocks}
        branch = []
        cur = node
        while cur.block.hash() not in active_hashes:
            branch.append(cur)
            cur = self.index[cur.parent_hash]
        fork_hash = cur.block.hash()
        branch.reverse()

        trial_utxo = copy.deepcopy(self.utxo)
        trial_blocks = list(self.blocks)
        trial_issued = self.total_issued

        while trial_blocks[-1].hash() != fork_hash:
            blk = trial_blocks.pop()
            undo = self.undo.get(blk.hash())
            if undo is None:
                return False, f"Missing active undo at {blk.height}", None, 0
            _undo_forward(undo, trial_utxo)
            trial_issued -= undo.reward

        for branch_node in branch:
            blk = branch_node.block
            height = len(trial_blocks)
            ok, reason, _undo, reward, _fees = _apply_forward(
                blk, trial_utxo, height, trial_issued
            )
            if not ok:
                return False, reason, None, 0
            trial_blocks.append(blk)
            trial_issued += reward

        return True, "OK", trial_utxo, trial_issued

    def _validate_side_block_state(self, block, parent_node, height):
        ok, reason, trial_utxo, trial_issued = self._state_for_index_node(parent_node)
        if not ok:
            return False, reason
        ok, reason, _undo, _reward, _fees = _apply_forward(
            block, trial_utxo, height, trial_issued
        )
        return ok, reason

    def balance(self, address):
'''
if source.count(anchor) != 1:
    raise SystemExit("SEC-106 helper anchor mismatch")
source = source.replace(anchor, replacement)

old = '''        cw = parent_node.chainwork + work_of(block.target)
        node = BlockNode(block, height, cw, parent)
        self.index[h] = node

        if parent == self.tip.hash():
'''
new = '''        cw = parent_node.chainwork + work_of(block.target)

        # A non-winning side branch used to be indexed after header/context
        # checks only. Validate its transaction transition and committed state
        # root now, so invalid branch state never becomes trusted index state.
        # Winning branches are validated atomically by _reorg_to below.
        if parent != self.tip.hash() and cw <= self.chainwork:
            ok, reason = self._validate_side_block_state(
                block, parent_node, height
            )
            if not ok:
                return False, reason

        node = BlockNode(block, height, cw, parent)
        self.index[h] = node

        if parent == self.tip.hash():
'''
if source.count(old) != 1:
    raise SystemExit("SEC-106 admission target mismatch")
source = source.replace(old, new)
path.write_text(source, encoding="utf-8", newline="\n")

spec = '''#!/usr/bin/env python3
"""SEC-106 side-chain state validation before index admission."""

import copy
import axven


def remine(block):
    block.nonce = 0
    while not block.pow_ok():
        block.nonce += 1
    return block


def main():
    active = axven.Blockchain()
    fork = axven.Blockchain()
    active_wallet = axven.Wallet()
    fork_wallet = axven.Wallet()

    for _ in range(4):
        active.mine(active_wallet.address)
    for _ in range(3):
        fork.mine(fork_wallet.address)

    ok, status = active.add_block(fork.blocks[1])
    assert ok and status == "side-chain"
    ok, status = active.add_block(fork.blocks[2])
    assert ok and status == "side-chain"
    print("[GREEN] valid side-chain state remains admissible")

    invalid = copy.deepcopy(fork.blocks[3])
    invalid.utxo_state_root = (
        "f" * 64 if invalid.utxo_state_root != "f" * 64 else "e" * 64
    )
    remine(invalid)
    invalid_hash = invalid.hash()
    before_index = set(active.index)

    ok, reason = active.add_block(invalid)
    assert not ok
    assert "state root" in reason.lower(), reason
    assert invalid_hash not in active.index
    assert set(active.index) == before_index
    print("[GREEN] invalid side-chain state root rejected before indexing")

    ok, status = active.add_block(fork.blocks[3])
    assert ok and status == "side-chain"
    assert fork.blocks[3].hash() in active.index
    print("[GREEN] canonical replacement side block accepted")

    fork.mine(fork_wallet.address)
    fork.mine(fork_wallet.address)
    statuses = []
    for block in fork.blocks[4:]:
        ok, status = active.add_block(block)
        assert ok, status
        statuses.append(status)

    assert "reorg" in statuses
    assert active.tip.hash() == fork.tip.hash()
    assert active.utxo == fork.utxo
    assert active.validate()
    print("[GREEN] validated side branch still performs heavier-chain reorg")

    source = open(axven.__file__, "r", encoding="utf-8").read()
    assert "_validate_side_block_state" in source
    assert "cw <= self.chainwork" in source
    print("[GREEN] side-chain admission validation is wired before index publish")

    print("SEC-106 side-chain state admission: 5/5 GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = Path("security_sec106_sidechain_state_validation_spec.py")
spec_path.write_text(spec, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("axven.py", spec_path.name):
    data = Path(name).read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest["files"] = dict(sorted(manifest["files"].items()))
manifest_path.write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
    newline="\n",
)
