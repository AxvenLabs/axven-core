#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    data = text.replace("\r\n", "\n").encode("utf-8")
    (ROOT / path).write_bytes(data)


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


ax = read("axven.py")
ax = replace_once(
    ax,
    "import threading\nfrom pathlib import Path\n",
    "import threading\nfrom collections import OrderedDict\nfrom pathlib import Path\n",
    "axven OrderedDict import",
)
ax = replace_once(
    ax,
    "MAX_MEMPOOL_TXS = 4096\nMAX_MEMPOOL_BYTES = 64 * 1024 * 1024\n",
    "MAX_MEMPOOL_TXS = 4096\nMAX_MEMPOOL_BYTES = 64 * 1024 * 1024\nMAX_VERIFIED_INPUT_CACHE = 32768\n",
    "verified input cache constant",
)

old = '''def _transition(block: Block, utxo: Dict[str, Dict[str, Any]], height: int, issued: int):
    \"\"\"Apply transactions in place WITHOUT checking the header state-root.\"\"\"
    txs = block.txs()
    coinbase = txs[0]
    spent, created, created_set, total_fees = [], [], set(), 0

    def rollback():
        for op in created:
            utxo.pop(op, None)
        for op, u in reversed(spent):
            if op not in created_set:
                utxo[op] = u

    for tx in txs[1:]:
        sh = tx.sighash()
        seen = set()
        in_sum = 0
        # Validate all inputs first against the current live state.
        for i in tx._in():
            op = outpoint(i.prev_txid, i.index)
            if op in seen:
                rollback(); return False, f\"Duplicate input at {height}\", None, 0, 0
            seen.add(op)
            u = utxo.get(op)
            if u is None:
                rollback(); return False, f\"Missing/spent input at {height}\", None, 0, 0
            if u[\"coinbase\"] and height - u[\"height\"] < COINBASE_MATURITY:
                rollback(); return False, f\"Immature coinbase spend at {height}\", None, 0, 0
            if not verify_input(i, u, sh, height):
                rollback(); return False, f\"Bad signature at {height}\", None, 0, 0
            in_sum += int(u[\"amount\"])
        out_sum = 0
        for o in tx.outputs:
            if o.amount < DUST:
                rollback(); return False, f\"Dust output at {height}\", None, 0, 0
            if not output_scheme_allowed(o.recipient, height):
                rollback(); return False, f\"Forbidden output scheme at {height}\", None, 0, 0
            out_sum += int(o.amount)
        if out_sum > in_sum:
            rollback(); return False, f\"Overspend at {height}\", None, 0, 0
        total_fees += in_sum - out_sum
        for i in tx._in():
            op = outpoint(i.prev_txid, i.index)
            u = utxo.pop(op)
            spent.append((op, u))
        tid = tx.txid()
        for idx, o in enumerate(tx.outputs):
            op = outpoint(tid, idx)
            utxo[op] = {\"amount\": o.amount, \"recipient\": o.recipient,
                        \"coinbase\": False, \"height\": height}
            created.append(op); created_set.add(op)

    reward = block_reward(height, issued)
    if len(coinbase.outputs) != 1:
        rollback(); return False, f\"Bad coinbase outputs at {height}\", None, 0, 0
    cbout = coinbase.outputs[0]
    if not output_scheme_allowed(cbout.recipient, height):
        rollback(); return False, f\"Forbidden coinbase output scheme at {height}\", None, 0, 0
    if cbout.amount != reward + total_fees:
        rollback(); return False, f\"Bad coinbase amount at {height}\", None, 0, 0
    cbid = coinbase.txid()
    op = outpoint(cbid, 0)
    utxo[op] = {\"amount\": cbout.amount, \"recipient\": cbout.recipient,
                \"coinbase\": True, \"height\": height}
    created.append(op); created_set.add(op)
    return True, \"OK\", BlockUndo(spent, created, reward), reward, total_fees
'''

new = '''class _VerifiedInputCache:
    \"\"\"Bounded positive-only LRU for exact successful input verifications.\"\"\"
    def __init__(self, max_entries=MAX_VERIFIED_INPUT_CACHE):
        if type(max_entries) is not int or max_entries < 1:
            raise ValueError(\"invalid verified-input cache bound\")
        self.max_entries = max_entries
        self._items = OrderedDict()
        self._lock = threading.Lock()

    def contains(self, key):
        with self._lock:
            if key not in self._items:
                return False
            self._items.move_to_end(key)
            return True

    def remember(self, key):
        with self._lock:
            self._items[key] = True
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def __len__(self):
        with self._lock:
            return len(self._items)


def _verified_input_cache_key(inp, utxo, sighash, height):
    payload = {
        \"height\": height,
        \"sighash\": sighash.hex(),
        \"input\": canonical_input(inp),
        \"utxo\": {
            \"amount\": utxo[\"amount\"],
            \"recipient\": utxo[\"recipient\"],
            \"coinbase\": utxo[\"coinbase\"],
            \"height\": utxo[\"height\"],
        },
    }
    return sha256(b\"axven-verified-input-v1|\" + canonical(payload))


def _transition(
    block: Block,
    utxo: Dict[str, Dict[str, Any]],
    height: int,
    issued: int,
    signature_work_gate=None,
    verification_cache=None,
):
    \"\"\"Apply transactions in place WITHOUT checking the header state-root.\"\"\"
    txs = block.txs()
    coinbase = txs[0]
    spent, created, created_set, total_fees = [], [], set(), 0
    auth_cost = {
        SCHEME_ED25519: 1,
        SCHEME_ML_DSA: 4,
        SCHEME_HYBRID: 5,
    }

    def rollback():
        for op in created:
            utxo.pop(op, None)
        for op, u in reversed(spent):
            if op not in created_set:
                utxo[op] = u

    for tx in txs[1:]:
        sh = tx.sighash()
        seen = set()
        in_sum = 0
        resolved = []
        # Resolve all cheap validity conditions before reserving scarce crypto
        # work.  Cache hits are exact positive results and require no crypto.
        for i in tx._in():
            op = outpoint(i.prev_txid, i.index)
            if op in seen:
                rollback(); return False, f\"Duplicate input at {height}\", None, 0, 0
            seen.add(op)
            u = utxo.get(op)
            if u is None:
                rollback(); return False, f\"Missing/spent input at {height}\", None, 0, 0
            if u[\"coinbase\"] and height - u[\"height\"] < COINBASE_MATURITY:
                rollback(); return False, f\"Immature coinbase spend at {height}\", None, 0, 0
            if not canonical_input_valid(i):
                rollback(); return False, f\"Bad signature at {height}\", None, 0, 0
            try:
                required_scheme = scheme_of_address(u[\"recipient\"])
            except ValueError:
                rollback(); return False, f\"Bad signature at {height}\", None, 0, 0
            supplied_scheme = _input_get(i, \"scheme\", \"\") or SCHEME_ED25519
            if supplied_scheme != required_scheme:
                rollback(); return False, f\"Bad signature at {height}\", None, 0, 0
            cache_key = _verified_input_cache_key(i, u, sh, height)
            cached = (
                verification_cache is not None
                and verification_cache.contains(cache_key)
            )
            resolved.append((i, u, cache_key, cached, auth_cost[required_scheme]))
            in_sum += int(u[\"amount\"])

        out_sum = 0
        for o in tx.outputs:
            if o.amount < DUST:
                rollback(); return False, f\"Dust output at {height}\", None, 0, 0
            if not output_scheme_allowed(o.recipient, height):
                rollback(); return False, f\"Forbidden output scheme at {height}\", None, 0, 0
            out_sum += int(o.amount)
        if out_sum > in_sum:
            rollback(); return False, f\"Overspend at {height}\", None, 0, 0

        crypto_work = sum(cost for _i, _u, _key, cached, cost in resolved if not cached)
        if (
            crypto_work
            and signature_work_gate is not None
            and not signature_work_gate(crypto_work)
        ):
            rollback(); return False, f\"Signature work budget exceeded at {height}\", None, 0, 0
        for i, u, cache_key, cached, _cost in resolved:
            if cached:
                continue
            if not verify_input(i, u, sh, height):
                rollback(); return False, f\"Bad signature at {height}\", None, 0, 0
            if verification_cache is not None:
                verification_cache.remember(cache_key)

        total_fees += in_sum - out_sum
        for i in tx._in():
            op = outpoint(i.prev_txid, i.index)
            u = utxo.pop(op)
            spent.append((op, u))
        tid = tx.txid()
        for idx, o in enumerate(tx.outputs):
            op = outpoint(tid, idx)
            utxo[op] = {\"amount\": o.amount, \"recipient\": o.recipient,
                        \"coinbase\": False, \"height\": height}
            created.append(op); created_set.add(op)

    reward = block_reward(height, issued)
    if len(coinbase.outputs) != 1:
        rollback(); return False, f\"Bad coinbase outputs at {height}\", None, 0, 0
    cbout = coinbase.outputs[0]
    if not output_scheme_allowed(cbout.recipient, height):
        rollback(); return False, f\"Forbidden coinbase output scheme at {height}\", None, 0, 0
    if cbout.amount != reward + total_fees:
        rollback(); return False, f\"Bad coinbase amount at {height}\", None, 0, 0
    cbid = coinbase.txid()
    op = outpoint(cbid, 0)
    utxo[op] = {\"amount\": cbout.amount, \"recipient\": cbout.recipient,
                \"coinbase\": True, \"height\": height}
    created.append(op); created_set.add(op)
    return True, \"OK\", BlockUndo(spent, created, reward), reward, total_fees
'''
ax = replace_once(ax, old, new, "transition replacement")

ax = replace_once(
    ax,
    '''def _apply_forward(block, utxo, height, issued):
    ok, reason, undo, reward, fees = _transition(block, utxo, height, issued)
''',
    '''def _apply_forward(
    block, utxo, height, issued, signature_work_gate=None, verification_cache=None
):
    ok, reason, undo, reward, fees = _transition(
        block, utxo, height, issued,
        signature_work_gate=signature_work_gate,
        verification_cache=verification_cache,
    )
''',
    "apply forward signature work",
)

ax = replace_once(
    ax,
    '''        self.mempool = None
        self._state_lock = threading.RLock()
        self._init_genesis()
''',
    '''        self.mempool = None
        self._state_lock = threading.RLock()
        self._verified_input_cache = _VerifiedInputCache()
        self._init_genesis()
''',
    "blockchain verification cache",
)

ax = replace_once(
    ax,
    '''    def _state_for_index_node(self, node):
        \"\"\"Build an isolated validated state snapshot at an indexed node.\"\"\"
''',
    '''    def _state_for_index_node(self, node, signature_work_gate=None):
        \"\"\"Build an isolated validated state snapshot at an indexed node.\"\"\"
''',
    "state for index signature gate",
)
ax = replace_once(
    ax,
    '''            ok, reason, _undo, reward, _fees = _apply_forward(
                blk, trial_utxo, height, trial_issued
            )
''',
    '''            ok, reason, _undo, reward, _fees = _apply_forward(
                blk, trial_utxo, height, trial_issued,
                signature_work_gate=signature_work_gate,
                verification_cache=self._verified_input_cache,
            )
''',
    "side replay signature cache",
)
ax = replace_once(
    ax,
    '''    def _validate_side_block_state(self, block, parent_node, height):
        ok, reason, trial_utxo, trial_issued = self._state_for_index_node(parent_node)
''',
    '''    def _validate_side_block_state(
        self, block, parent_node, height, signature_work_gate=None
    ):
        ok, reason, trial_utxo, trial_issued = self._state_for_index_node(
            parent_node, signature_work_gate=signature_work_gate
        )
''',
    "side state signature gate",
)
ax = replace_once(
    ax,
    '''        ok, reason, _undo, _reward, _fees = _apply_forward(
            block, trial_utxo, height, trial_issued
        )
''',
    '''        ok, reason, _undo, _reward, _fees = _apply_forward(
            block, trial_utxo, height, trial_issued,
            signature_work_gate=signature_work_gate,
            verification_cache=self._verified_input_cache,
        )
''',
    "incoming side signature cache",
)

ax = replace_once(
    ax,
    '''    def add_block(self, block, work_gate=None):
        with self._state_lock:
            return self._add_block_locked(block, work_gate=work_gate)

    def _add_block_locked(self, block, work_gate=None):
''',
    '''    def add_block(self, block, work_gate=None, signature_work_gate=None):
        with self._state_lock:
            return self._add_block_locked(
                block,
                work_gate=work_gate,
                signature_work_gate=signature_work_gate,
            )

    def _add_block_locked(self, block, work_gate=None, signature_work_gate=None):
''',
    "add block signature gate",
)
ax = replace_once(
    ax,
    '''            ok, reason = self._validate_side_block_state(
                block, parent_node, height
            )
''',
    '''            ok, reason = self._validate_side_block_state(
                block, parent_node, height,
                signature_work_gate=signature_work_gate,
            )
''',
    "nonwinning side signature gate",
)
ax = replace_once(
    ax,
    '''            ok, reason, undo, reward, _fees = _apply_forward(
                block, self.utxo, height, self.total_issued
            )
''',
    '''            ok, reason, undo, reward, _fees = _apply_forward(
                block, self.utxo, height, self.total_issued,
                signature_work_gate=signature_work_gate,
                verification_cache=self._verified_input_cache,
            )
''',
    "active extension signature gate",
)
ax = replace_once(
    ax,
    '''            ok, reason = self._reorg_to(node)
''',
    '''            ok, reason = self._reorg_to(
                node, signature_work_gate=signature_work_gate
            )
''',
    "reorg signature gate call",
)
ax = replace_once(
    ax,
    '''        self._connect_orphans(h, work_gate=work_gate)
        return True, status

    def _reorg_to(self, node):
''',
    '''        self._connect_orphans(
            h,
            work_gate=work_gate,
            signature_work_gate=signature_work_gate,
        )
        return True, status

    def _reorg_to(self, node, signature_work_gate=None):
''',
    "orphan and reorg signature gate",
)
ax = replace_once(
    ax,
    '''            ok, reason, undo, reward, _fees = _apply_forward(blk, tu, hh, tissued)
''',
    '''            ok, reason, undo, reward, _fees = _apply_forward(
                blk, tu, hh, tissued,
                signature_work_gate=signature_work_gate,
                verification_cache=self._verified_input_cache,
            )
''',
    "reorg replay signature cache",
)
ax = replace_once(
    ax,
    '''    def _connect_orphans(self, h, work_gate=None):
''',
    '''    def _connect_orphans(
        self, h, work_gate=None, signature_work_gate=None
    ):
''',
    "connect orphan signature gate",
)
ax = replace_once(
    ax,
    '''                ok, _ = self.add_block(child, work_gate=work_gate)
''',
    '''                ok, _ = self.add_block(
                    child,
                    work_gate=work_gate,
                    signature_work_gate=signature_work_gate,
                )
''',
    "orphan child signature gate",
)
write("axven.py", ax)

p2p = read("p2p.py")
p2p = replace_once(
    p2p,
    '''MAX_INBOUND_TX_WORK_HOSTS = 1024
MAX_P2P_MESSAGE_TYPE_CHARS = 32
''',
    '''MAX_INBOUND_TX_WORK_HOSTS = 1024
# A valid Ed25519 input needs at least 88 base64 signature chars plus 44
# base64 public-key chars.  Ed25519 is the densest supported scheme per work
# unit, so this derives a conservative fresh-burst upper bound from the
# consensus block byte cap without changing block validity.
MIN_VALID_ED25519_AUTH_TEXT_BYTES = 132
MAX_VALID_BLOCK_SIGNATURE_WORK = (
    int(axven.CHAIN_CONFIG["max_block_bytes"]) // MIN_VALID_ED25519_AUTH_TEXT_BYTES
    + 1
)
INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_RATE = 4096.0
INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK * 4
INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_RATE = 1024.0
INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK
MAX_INBOUND_BLOCK_SIGNATURE_WORK_HOSTS = 1024
MAX_P2P_MESSAGE_TYPE_CHARS = 32
''',
    "block signature work constants",
)

anchor = '''    def snapshot(self):
        with self._lock:
            return {
                "global_tokens": self._global_tokens,
                "hosts": len(self._hosts),
            }


def _reject_duplicate_json_keys(pairs):
'''
replacement = '''    def snapshot(self):
        with self._lock:
            return {
                "global_tokens": self._global_tokens,
                "hosts": len(self._hosts),
            }


class _InboundBlockSignatureWorkLimiter(_InboundTxWorkLimiter):
    \"\"\"Weighted public block signature budget with a full-block fresh burst.\"\"\"
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_RATE,
        global_burst=INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_BURST,
        per_host_rate=INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_RATE,
        per_host_burst=INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST,
        max_hosts=MAX_INBOUND_BLOCK_SIGNATURE_WORK_HOSTS,
    ):
        super().__init__(
            clock=clock,
            global_rate=global_rate,
            global_burst=global_burst,
            per_host_rate=per_host_rate,
            per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


def _reject_duplicate_json_keys(pairs):
'''
# The snapshot anchor occurs once at the end of _InboundTxWorkLimiter because
# the preceding block-work limiter snapshot has an additional blank region.
pos = p2p.rfind(anchor)
if pos < 0:
    raise AssertionError("block signature limiter insertion anchor missing")
p2p = p2p[:pos] + replacement + p2p[pos + len(anchor):]

p2p = replace_once(
    p2p,
    '''    def handle(self,msg,block_work_gate=None,tx_work_gate=None):
''',
    '''    def handle(
        self, msg, block_work_gate=None, tx_work_gate=None,
        block_signature_work_gate=None,
    ):
''',
    "PeerSession signature gate",
)

old = '''            block=axven.Block.from_dict(raw_block)
            if block_work_gate is None:
                ok,status=self.chain.add_block(block)
            else:
                ok,status=self.chain.add_block(block,work_gate=block_work_gate)
'''
new = '''            block=axven.Block.from_dict(raw_block)
            if block_work_gate is None and block_signature_work_gate is None:
                ok,status=self.chain.add_block(block)
            else:
                kwargs={}
                if block_work_gate is not None:
                    kwargs["work_gate"]=block_work_gate
                if block_signature_work_gate is not None:
                    kwargs["signature_work_gate"]=block_signature_work_gate
                ok,status=self.chain.add_block(block,**kwargs)
'''
p2p = replace_once(p2p, old, new, "standalone block signature gate")

old = '''                b=axven.Block.from_dict(raw)
                if block_work_gate is None:
                    ok,status=self.chain.add_block(b)
                else:
                    ok,status=self.chain.add_block(b,work_gate=block_work_gate)
'''
new = '''                b=axven.Block.from_dict(raw)
                if block_work_gate is None and block_signature_work_gate is None:
                    ok,status=self.chain.add_block(b)
                else:
                    kwargs={}
                    if block_work_gate is not None:
                        kwargs["work_gate"]=block_work_gate
                    if block_signature_work_gate is not None:
                        kwargs["signature_work_gate"]=block_signature_work_gate
                    ok,status=self.chain.add_block(b,**kwargs)
'''
p2p = replace_once(p2p, old, new, "block batch signature gate")

p2p = replace_once(
    p2p,
    '''def serve_connection(
    sock,session:PeerSession,block_work_gate=None,tx_work_gate=None
):
''',
    '''def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None,
):
''',
    "serve connection signature gate",
)
p2p = replace_once(
    p2p,
    '''            if tx_work_gate is not None:
                reply=session.handle(
                    msg,
                    block_work_gate=block_work_gate,
                    tx_work_gate=tx_work_gate,
                )
            elif block_work_gate is not None:
                reply=session.handle(msg,block_work_gate=block_work_gate)
            else:
                reply=session.handle(msg)
''',
    '''            if tx_work_gate is not None or block_signature_work_gate is not None:
                reply=session.handle(
                    msg,
                    block_work_gate=block_work_gate,
                    tx_work_gate=tx_work_gate,
                    block_signature_work_gate=block_signature_work_gate,
                )
            elif block_work_gate is not None:
                reply=session.handle(msg,block_work_gate=block_work_gate)
            else:
                reply=session.handle(msg)
''',
    "serve connection forwarding",
)
p2p = replace_once(
    p2p,
    '''        self._block_work_limiter=_InboundBlockWorkLimiter()
        self._tx_work_limiter=_InboundTxWorkLimiter()
''',
    '''        self._block_work_limiter=_InboundBlockWorkLimiter()
        self._tx_work_limiter=_InboundTxWorkLimiter()
        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()
''',
    "NodeServer block signature limiter",
)
p2p = replace_once(
    p2p,
    '''                    tx_gate=lambda cost: self._tx_work_limiter.consume(
                        source_host,cost
                    )
                    try:
                        serve_connection(
                            client,self.session,
                            block_work_gate=block_gate,
                            tx_work_gate=tx_gate,
                        )
''',
    '''                    tx_gate=lambda cost: self._tx_work_limiter.consume(
                        source_host,cost
                    )
                    block_signature_gate=lambda cost: (
                        self._block_signature_work_limiter.consume(source_host,cost)
                    )
                    try:
                        serve_connection(
                            client,self.session,
                            block_work_gate=block_gate,
                            tx_work_gate=tx_gate,
                            block_signature_work_gate=block_signature_gate,
                        )
''',
    "NodeServer signature gate wiring",
)
write("p2p.py", p2p)

spec = r'''#!/usr/bin/env python3
"""SEC-120 bound block-contained signature verification and fork replay work."""

import copy
import inspect
import axven
import p2p


class FakeClock:
    def __init__(self):
        self.now = 1000.0
    def __call__(self):
        return self.now
    def advance(self, seconds):
        self.now += seconds


def mine_chain(count, wallet):
    chain = axven.Blockchain()
    for _ in range(count):
        chain.mine(wallet.address)
    return chain


def replay_prefix(source, height):
    out = axven.Blockchain()
    for block in source.blocks[1:height + 1]:
        ok, status = out.add_block(block)
        assert ok and status == "extended"
    return out


def add_signed_spend(chain, wallet, recipient=None):
    recipient = recipient or axven.Wallet().address
    txid, index, amount = chain.spendable(wallet.address)[0]
    tx = axven.Transaction(
        [axven.TxInput(txid, index)],
        [axven.TxOutput(amount - 1, recipient)],
    )
    tx.inputs[0] = wallet.sign_input(tx, 0)
    mp = axven.Mempool(chain)
    mp.add(tx)
    return tx, chain.build_candidate(wallet.address, mp)


def main():
    checks = []
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "block signature work budgets and cache bound are pinned safely",
        axven.MAX_VERIFIED_INPUT_CACHE == 32768
        and p2p.MIN_VALID_ED25519_AUTH_TEXT_BYTES == 132
        and p2p.MAX_VALID_BLOCK_SIGNATURE_WORK
            > int(axven.CHAIN_CONFIG["max_block_bytes"]) // 132
        and p2p.INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST
            == p2p.MAX_VALID_BLOCK_SIGNATURE_WORK
        and p2p.INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_BURST
            >= 4 * p2p.INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST,
    )

    clock = FakeClock()
    limiter = p2p._InboundBlockSignatureWorkLimiter(
        clock=clock, global_rate=10, global_burst=20,
        per_host_rate=5, per_host_burst=10, max_hosts=2,
    )
    green(
        "single source weighted block signature burst is bounded",
        limiter.consume("192.0.2.1", 6)
        and not limiter.consume("192.0.2.1", 5),
    )
    clock.advance(1.0)
    green(
        "block signature work budget refills at configured rate",
        limiter.consume("192.0.2.1", 5),
    )
    distributed = p2p._InboundBlockSignatureWorkLimiter(
        clock=FakeClock(), global_rate=1, global_burst=8,
        per_host_rate=1, per_host_burst=8, max_hosts=4,
    )
    green(
        "distributed block signature sources remain globally bounded",
        distributed.consume("192.0.2.10", 4)
        and distributed.consume("192.0.2.11", 4)
        and not distributed.consume("192.0.2.12", 1),
    )
    mem = p2p._InboundBlockSignatureWorkLimiter(
        clock=FakeClock(), global_rate=100, global_burst=100,
        per_host_rate=100, per_host_burst=100, max_hosts=2,
    )
    mem.consume("198.51.100.1", 1)
    mem.consume("198.51.100.2", 1)
    mem.consume("198.51.100.3", 1)
    green("block signature limiter source memory is bounded", mem.snapshot()["hosts"] == 2)

    cache = axven._VerifiedInputCache(max_entries=2)
    cache.remember("a"); cache.remember("b")
    assert cache.contains("a")
    cache.remember("c")
    green(
        "positive verification cache is bounded LRU",
        len(cache) == 2 and cache.contains("a") and cache.contains("c")
        and not cache.contains("b"),
    )

    miner = axven.Wallet()
    source = mine_chain(axven.COINBASE_MATURITY + 1, miner)
    tx, block = add_signed_spend(source, miner)
    base_utxo = copy.deepcopy(source.utxo)
    base_issued = source.total_issued
    height = source.tip.height + 1
    shared_cache = axven._VerifiedInputCache()
    verify_calls = []
    gate_calls = []
    original_verify = axven.verify_input
    def counted_verify(*args, **kwargs):
        verify_calls.append(1)
        return original_verify(*args, **kwargs)
    axven.verify_input = counted_verify
    try:
        first_utxo = copy.deepcopy(base_utxo)
        ok, reason, _undo, _reward, _fees = axven._apply_forward(
            block, first_utxo, height, base_issued,
            signature_work_gate=lambda cost: gate_calls.append(cost) or True,
            verification_cache=shared_cache,
        )
        first_calls = len(verify_calls)
        second_gate = []
        second_utxo = copy.deepcopy(base_utxo)
        ok2, reason2, _undo2, _reward2, _fees2 = axven._apply_forward(
            block, second_utxo, height, base_issued,
            signature_work_gate=lambda cost: second_gate.append(cost) or True,
            verification_cache=shared_cache,
        )
    finally:
        axven.verify_input = original_verify
    green(
        "fresh valid block charges exact Ed25519 work before one verify",
        ok and reason == "OK" and gate_calls == [1] and first_calls == 1,
    )
    green(
        "exact positive cache hit skips repeated crypto and preserves state",
        ok2 and reason2 == "OK" and len(verify_calls) == first_calls
        and second_gate == [] and second_utxo == first_utxo,
    )

    blocked_utxo = copy.deepcopy(base_utxo)
    before_blocked = copy.deepcopy(blocked_utxo)
    called = []
    def forbidden_verify(*_args, **_kwargs):
        called.append(1)
        raise AssertionError("verify_input ran after exhausted work gate")
    axven.verify_input = forbidden_verify
    try:
        ok, reason, *_ = axven._apply_forward(
            block, blocked_utxo, height, base_issued,
            signature_work_gate=lambda _cost: False,
            verification_cache=axven._VerifiedInputCache(),
        )
    finally:
        axven.verify_input = original_verify
    green(
        "exhausted block signature budget stops before crypto and rolls back",
        (not ok) and "Signature work budget exceeded" in reason
        and called == [] and blocked_utxo == before_blocked,
    )

    bad_output = copy.deepcopy(block)
    bad_output.transactions[1]["outputs"][0]["amount"] = 0
    cheap_gate = []
    called = []
    axven.verify_input = forbidden_verify
    try:
        bad_utxo = copy.deepcopy(base_utxo)
        ok, reason, *_ = axven._transition(
            bad_output, bad_utxo, height, base_issued,
            signature_work_gate=lambda cost: cheap_gate.append(cost) or True,
            verification_cache=axven._VerifiedInputCache(),
        )
    finally:
        axven.verify_input = original_verify
    green(
        "cheap invalid block output consumes no signature work",
        (not ok) and "Dust output" in reason and cheap_gate == [] and called == [],
    )

    bad_sig = copy.deepcopy(block)
    bad_sig.transactions[1]["inputs"][0]["signature"] = "AAAA"
    failed_cache = axven._VerifiedInputCache()
    failed_gate = []
    bad_utxo = copy.deepcopy(base_utxo)
    ok, reason, *_ = axven._transition(
        bad_sig, bad_utxo, height, base_issued,
        signature_work_gate=lambda cost: failed_gate.append(cost) or True,
        verification_cache=failed_cache,
    )
    green(
        "failed signature is charged but never cached",
        (not ok) and "Bad signature" in reason and failed_gate == [1]
        and len(failed_cache) == 0,
    )

    target = replay_prefix(source, source.tip.height)
    verify_calls = []
    axven.verify_input = counted_verify
    try:
        ok, reason = target.add_block(
            block, signature_work_gate=lambda _cost: False
        )
    finally:
        axven.verify_input = original_verify
    green(
        "Blockchain enforces signature work gate before verification",
        (not ok) and "Signature work budget exceeded" in reason and verify_calls == [],
    )

    target2 = replay_prefix(source, source.tip.height)
    session = p2p.PeerSession(target2, None)
    try:
        session.handle(
            {"type": "block", "block": block.to_dict()},
            block_work_gate=lambda: True,
            block_signature_work_gate=lambda _cost: False,
        )
        peer_blocked = False
    except p2p.ProtocolError as exc:
        peer_blocked = "Signature work budget exceeded" in str(exc)
    green("PeerSession enforces public block signature gate", peer_blocked)

    # Exercise the real fork-replay amplifier: the side block contains one
    # signed spend, then a child makes the branch heavier.  The already
    # positively verified side signature must not run again during reorg replay.
    active = mine_chain(axven.COINBASE_MATURITY + 1, miner)
    fork_parent_height = active.tip.height - 1
    side_builder = replay_prefix(active, fork_parent_height)
    _side_tx, side_block = add_signed_spend(side_builder, miner)
    ok, status = active.add_block(
        side_block, signature_work_gate=lambda _cost: True
    )
    assert ok and status == "side-chain"
    ok, status = side_builder.add_block(side_block)
    assert ok and status == "extended"
    child = side_builder.build_candidate(miner.address)
    replay_verify_calls = []
    def replay_counted(*args, **kwargs):
        replay_verify_calls.append(1)
        return original_verify(*args, **kwargs)
    axven.verify_input = replay_counted
    try:
        ok, status = active.add_block(
            child, signature_work_gate=lambda _cost: True
        )
    finally:
        axven.verify_input = original_verify
    green(
        "heavier fork replay reuses exact positive signatures without reverify",
        ok and status == "reorg" and replay_verify_calls == [] and active.validate(),
    )

    class LegacyCompatibleChain:
        def __init__(self): self.seen = []
        def add_block(self, candidate):
            self.seen.append(candidate)
            return True, "extended"
    legacy = LegacyCompatibleChain()
    reply = p2p.PeerSession(legacy, None).handle(
        {"type": "block", "block": block.to_dict()}
    )
    green(
        "unmetered block session preserves legacy add_block call shape",
        reply["type"] == "accepted" and reply["status"] == "extended"
        and len(legacy.seen) == 1,
    )

    trans_src = inspect.getsource(axven._transition)
    state_src = inspect.getsource(axven.Blockchain._state_for_index_node)
    reorg_src = inspect.getsource(axven.Blockchain._reorg_to)
    orphan_src = inspect.getsource(axven.Blockchain._connect_orphans)
    serve_src = inspect.getsource(p2p.serve_connection)
    server_src = inspect.getsource(p2p.NodeServer.start)
    validate_src = inspect.getsource(axven.Blockchain.validate_reason)
    green(
        "production wiring meters uncached block crypto while full validation stays independent",
        "signature_work_gate(crypto_work)" in trans_src
        and trans_src.index("signature_work_gate(crypto_work)") < trans_src.index("verify_input(i, u, sh, height)")
        and "verification_cache=self._verified_input_cache" in state_src
        and "verification_cache=self._verified_input_cache" in reorg_src
        and "signature_work_gate=signature_work_gate" in orphan_src
        and "block_signature_work_gate=block_signature_work_gate" in serve_src
        and "_block_signature_work_limiter.consume(source_host,cost)" in server_src
        and "verification_cache" not in validate_src
        and "signature_work_gate" not in validate_src,
    )

    print(f"SEC-120 block signature work: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
write("security_sec120_block_signature_work_spec.py", spec)

# Refresh release manifest for exact LF bytes of modified/new shipped files.
manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in (
    "axven.py",
    "p2p.py",
    "security_sec120_block_signature_work_spec.py",
):
    data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
    (ROOT / name).write_bytes(data)
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
write("release_manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print("SEC-120 patch staged with LF-normalized manifest hashes")
