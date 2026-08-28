#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
AXVEN = ROOT / "axven.py"
SPEC = ROOT / "security_sec117_sidefork_cow_utxo_spec.py"
MANIFEST = ROOT / "release_manifest.json"


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"{label}: expected exactly one anchor, got {count}")
    return text.replace(old, new, 1)


def write_lf(path, text):
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


src = AXVEN.read_text(encoding="utf-8").replace("\r\n", "\n")

overlay = '''class _UTXOOverlay:
    """Copy-on-write UTXO view for tentative validation/reorg state.

    Reads fall through to the live base mapping while writes/deletes are kept
    in a small delta.  The live base is never mutated.  Full materialization
    is reserved for a successfully validated reorg publication.
    """
    _MISSING = object()

    def __init__(self, base):
        self._base = base
        self._writes = {}
        self._deleted = set()

    @property
    def delta_size(self):
        return len(self._writes) + len(self._deleted)

    def __contains__(self, key):
        return key in self._writes or (
            key not in self._deleted and key in self._base
        )

    def __getitem__(self, key):
        if key in self._writes:
            return self._writes[key]
        if key in self._deleted:
            raise KeyError(key)
        return self._base[key]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __setitem__(self, key, value):
        self._writes[key] = value
        self._deleted.discard(key)

    def __delitem__(self, key):
        if key in self._writes:
            self._writes.pop(key)
            if key in self._base:
                self._deleted.add(key)
            else:
                self._deleted.discard(key)
            return
        if key in self._deleted or key not in self._base:
            raise KeyError(key)
        self._deleted.add(key)

    def pop(self, key, default=_MISSING):
        try:
            value = self[key]
        except KeyError:
            if default is self._MISSING:
                raise
            return default
        del self[key]
        return value

    def __iter__(self):
        for key in self._base:
            if key not in self._deleted:
                yield key
        for key in self._writes:
            if key not in self._base:
                yield key

    def __len__(self):
        removed = sum(1 for key in self._deleted if key in self._base)
        added = sum(1 for key in self._writes if key not in self._base)
        return len(self._base) - removed + added

    def items(self):
        for key in self:
            yield key, self[key]

    def materialize(self):
        return {key: dict(value) for key, value in self.items()}


'''

src = replace_once(
    src,
    "class _IndexedBlockPath:\n",
    overlay + "class _IndexedBlockPath:\n",
    "overlay insertion",
)

state_anchor = '''        trial_utxo = copy.deepcopy(self.utxo)\n        trial_blocks = list(self.blocks)\n        trial_issued = self.total_issued\n'''
state_repl = '''        trial_utxo = _UTXOOverlay(self.utxo)\n        trial_blocks = list(self.blocks)\n        trial_issued = self.total_issued\n'''
src = replace_once(src, state_anchor, state_repl, "side-state COW")

reorg_anchor = '''    def _reorg_to(self, node):\n        tu = copy.deepcopy(self.utxo)\n        tblocks = list(self.blocks)\n'''
reorg_repl = '''    def _reorg_to(self, node):\n        tu = _UTXOOverlay(self.utxo)\n        tblocks = list(self.blocks)\n'''
src = replace_once(src, reorg_anchor, reorg_repl, "reorg COW")

publish_anchor = '''        self.utxo, self.blocks = tu, tblocks\n        self.total_issued, self.chainwork, self.undo = tissued, tcw, tundo\n'''
publish_repl = '''        materialized_utxo = tu.materialize()\n        self.utxo, self.blocks = materialized_utxo, tblocks\n        self.total_issued, self.chainwork, self.undo = tissued, tcw, tundo\n'''
src = replace_once(src, publish_anchor, publish_repl, "reorg materialization")
write_lf(AXVEN, src)

spec = r'''#!/usr/bin/env python3
"""SEC-117 bound tentative side/reorg UTXO copy amplification."""

import copy
import inspect
import axven


def mine_chain(count, wallet=None):
    chain = axven.Blockchain()
    wallet = wallet or axven.Wallet()
    for _ in range(count):
        chain.mine(wallet.address)
    return chain


def replay_prefix(chain, height):
    out = axven.Blockchain()
    for block in chain.blocks[1:height + 1]:
        ok, status = out.add_block(block)
        assert ok and status == "extended"
    return out


def remine(block):
    block.nonce = 0
    while not block.pow_ok():
        block.nonce += 1
    return block


def main():
    checks = []

    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    base = {
        f"{i:064x}:0": {
            "amount": i + 1,
            "recipient": "N" + f"{i:040x}"[-40:],
            "coinbase": False,
            "height": 1,
        }
        for i in range(4096)
    }
    overlay = axven._UTXOOverlay(base)
    green(
        "overlay starts O(1) over live base",
        overlay._base is base and overlay.delta_size == 0 and len(overlay) == len(base),
    )

    expected = copy.deepcopy(base)
    spent = next(iter(base))
    new_op = "f" * 64 + ":1"
    old = overlay.pop(spent)
    expected.pop(spent)
    overlay[new_op] = {
        "amount": 777,
        "recipient": "N" + "a" * 40,
        "coinbase": False,
        "height": 2,
    }
    expected[new_op] = dict(overlay[new_op])
    green(
        "overlay mutations remain delta-sized and base-isolated",
        overlay.delta_size == 2 and spent in base and new_op not in base,
    )
    overlay[spent] = old
    expected[spent] = old
    materialized = overlay.materialize()
    green(
        "overlay materialization matches ordinary dict semantics",
        materialized == expected and type(materialized) is dict,
    )

    legacy_height = 9
    sparse_height = int(axven.CHAIN_CONFIG["smt_activation_height"])
    small_base = dict(list(base.items())[:32])
    small_overlay = axven._UTXOOverlay(small_base)
    small_overlay.pop(next(iter(small_base)))
    small_overlay[new_op] = expected[new_op]
    small_expected = small_overlay.materialize()
    green(
        "state-root oracle is identical for overlay and dict state",
        axven.expected_state_root(small_overlay, legacy_height)
        == axven.expected_state_root(small_expected, legacy_height)
        and axven.expected_state_root(small_overlay, sparse_height)
        == axven.expected_state_root(small_expected, sparse_height),
    )

    active = mine_chain(6)
    parent_height = active.tip.height - 1
    sibling_builder = replay_prefix(active, parent_height)
    sibling = sibling_builder.build_candidate(axven.Wallet().address)
    active_before = copy.deepcopy(active.utxo)

    class NoDeepcopy:
        @staticmethod
        def deepcopy(*_args, **_kwargs):
            raise AssertionError("tentative network fork path attempted deepcopy")

    old_copy_module = axven.copy
    axven.copy = NoDeepcopy()
    try:
        ok, status = active.add_block(sibling)
    finally:
        axven.copy = old_copy_module
    green(
        "valid non-winning side admission performs no full UTXO deepcopy",
        ok and status == "side-chain" and active.utxo == active_before,
    )

    bad_builder = replay_prefix(active, parent_height)
    bad_side = bad_builder.build_candidate(axven.Wallet().address)
    bad_side.utxo_state_root = "11" * 32
    remine(bad_side)
    active_before_bad = copy.deepcopy(active.utxo)
    old_copy_module = axven.copy
    axven.copy = NoDeepcopy()
    try:
        ok, reason = active.add_block(bad_side)
    finally:
        axven.copy = old_copy_module
    green(
        "invalid side state fails without copying or mutating live UTXO",
        (not ok)
        and "state root" in reason.lower()
        and active.utxo == active_before_bad,
    )

    active2 = mine_chain(2)
    fork2 = mine_chain(3)
    ok, status = active2.add_block(fork2.blocks[1])
    assert ok and status == "side-chain"
    ok, status = active2.add_block(fork2.blocks[2])
    assert ok and status == "side-chain"

    invalid_winner = copy.deepcopy(fork2.blocks[3])
    invalid_winner.utxo_state_root = "22" * 32
    remine(invalid_winner)
    before_tip = active2.tip.hash()
    before_utxo = copy.deepcopy(active2.utxo)
    old_copy_module = axven.copy
    axven.copy = NoDeepcopy()
    try:
        ok, reason = active2.add_block(invalid_winner)
    finally:
        axven.copy = old_copy_module
    green(
        "invalid heavier fork aborts without full UTXO deepcopy",
        (not ok)
        and "reorg aborted" in reason.lower()
        and active2.tip.hash() == before_tip
        and active2.utxo == before_utxo,
    )

    ok, status = active2.add_block(fork2.blocks[3])
    green(
        "valid heavier reorg still materializes exact plain-dict state",
        ok
        and status == "reorg"
        and type(active2.utxo) is dict
        and active2.utxo == fork2.utxo
        and active2.validate(),
    )

    state_src = inspect.getsource(axven.Blockchain._state_for_index_node)
    reorg_src = inspect.getsource(axven.Blockchain._reorg_to)
    green(
        "production tentative fork paths are wired to copy-on-write state",
        "_UTXOOverlay(self.utxo)" in state_src
        and "copy.deepcopy(self.utxo)" not in state_src
        and "_UTXOOverlay(self.utxo)" in reorg_src
        and "copy.deepcopy(self.utxo)" not in reorg_src
        and ".materialize()" in reorg_src,
    )

    print(f"SEC-117 side-fork COW UTXO: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
write_lf(SPEC, spec)

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for rel in ("axven.py", SPEC.name):
    data = (ROOT / rel).read_bytes().replace(b"\r\n", b"\n")
    # Ensure the working tree bytes are exactly the bytes that are hashed.
    (ROOT / rel).write_bytes(data)
    manifest["files"][rel] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
axven_bytes = AXVEN.read_bytes()
manifest["consensus_code_sha256"] = hashlib.sha256(axven_bytes).hexdigest()
manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
MANIFEST.write_bytes(manifest_bytes)
print("SEC-117 patch staged with LF-normalized manifest hashes")
