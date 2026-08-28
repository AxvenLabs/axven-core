#!/usr/bin/env python3
from pathlib import Path

# Normalize the one production formatting anchor expected by the fail-closed
# patch helper.  This is formatting-only and is replaced by the real patch.
path = Path("axven.py")
text = path.read_text(encoding="utf-8")
old = '''            ok, reason, undo, reward, _fees = _apply_forward(
                block, self.utxo, height, self.total_issued)
'''
new = '''            ok, reason, undo, reward, _fees = _apply_forward(
                block, self.utxo, height, self.total_issued
            )
'''
if text.count(old) != 1:
    raise AssertionError(f"active-extension normalization anchor count={text.count(old)}")
path.write_bytes(text.replace(old, new, 1).replace("\r\n", "\n").encode("utf-8"))

# The SEC-120 fork-replay fixture must fork from a height where the first
# coinbase is already mature.  Correct only the generated test fixture in the
# helper before it runs; no production behavior is altered here.
helper = Path(".github/sec120_apply.py")
htext = helper.read_text(encoding="utf-8")
fixture_old = '    active = mine_chain(axven.COINBASE_MATURITY + 1, miner)\n    fork_parent_height = active.tip.height - 1\n'
fixture_new = '    active = mine_chain(axven.COINBASE_MATURITY + 2, miner)\n    fork_parent_height = active.tip.height - 1\n'
if htext.count(fixture_old) != 1:
    raise AssertionError(f"fork maturity fixture anchor count={htext.count(fixture_old)}")
helper.write_bytes(htext.replace(fixture_old, fixture_new, 1).replace("\r\n", "\n").encode("utf-8"))
print("SEC-120 patch/test anchors normalized")
