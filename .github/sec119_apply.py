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
    p.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


# Mempool: preserve atomic chain->mempool locking, but reserve weighted work
# only after all cheap admission checks and immediately before signature work.
old_mempool = '''    def add(self, tx: Transaction) -> str:\n        # UTXO/tip validation and mempool conflict publication are one atomic\n        # operation.  Keep the global lock order chain -> mempool.\n        with self.chain._state_lock:\n            with self._lock:\n                return self._add_locked(tx)\n\n    def _add_locked(self, tx: Transaction) -> str:\n        if tx.is_coinbase:\n            raise ValueError("Coinbase cannot enter the mempool")\n        tid = tx.txid()\n        if tid in self.txs:\n            raise ValueError("Already in mempool")\n        if len(self.txs) >= MAX_MEMPOOL_TXS:\n            raise ValueError("Mempool full")\n        tx_bytes = serialized_transaction_size(tx)\n        if self.total_bytes + tx_bytes > MAX_MEMPOOL_BYTES:\n            raise ValueError("Mempool byte budget full")\n        ops = [outpoint(i.prev_txid, i.index) for i in tx._in()]\n        if len(ops) != len(set(ops)) or any(op in self.spent for op in ops):\n            raise ValueError("Double spend")\n        in_sum = 0\n        sh = tx.sighash()\n        for i, op in zip(tx._in(), ops):\n            u = self.chain.utxo.get(op)\n            if u is None:\n                raise ValueError("Input not found / unconfirmed")\n            if u["coinbase"] and self.chain.tip.height - u["height"] < COINBASE_MATURITY:\n                raise ValueError("Coinbase not mature")\n            if not verify_input(i, u, sh, self.chain.tip.height + 1):\n                raise ValueError("Bad signature")\n            in_sum += u["amount"]\n        out_sum = 0\n        for o in tx.outputs:\n            if o.amount < DUST:\n                raise ValueError("Dust / non-positive output")\n            if not output_scheme_allowed(o.recipient, self.chain.tip.height + 1):\n                raise ValueError("Forbidden output scheme")\n            out_sum += o.amount\n        if out_sum > in_sum:\n            raise ValueError("Outputs exceed inputs")\n        self.txs[tid] = tx\n        self.fees[tid] = in_sum - out_sum\n        self.tx_sizes[tid] = tx_bytes\n        self.total_bytes += tx_bytes\n        self.spent.update(ops)\n        return tid\n'''
new_mempool = '''    def add(self, tx: Transaction, work_gate=None) -> str:\n        # UTXO/tip validation and mempool conflict publication are one atomic\n        # operation.  Keep the global lock order chain -> mempool.\n        with self.chain._state_lock:\n            with self._lock:\n                if work_gate is None:\n                    return self._add_locked(tx)\n                return self._add_locked(tx, work_gate=work_gate)\n\n    def _add_locked(self, tx: Transaction, work_gate=None) -> str:\n        if tx.is_coinbase:\n            raise ValueError("Coinbase cannot enter the mempool")\n        tid = tx.txid()\n        if tid in self.txs:\n            raise ValueError("Already in mempool")\n        if len(self.txs) >= MAX_MEMPOOL_TXS:\n            raise ValueError("Mempool full")\n        tx_bytes = serialized_transaction_size(tx)\n        if self.total_bytes + tx_bytes > MAX_MEMPOOL_BYTES:\n            raise ValueError("Mempool byte budget full")\n        inputs = tx._in()\n        ops = [outpoint(i.prev_txid, i.index) for i in inputs]\n        if len(ops) != len(set(ops)) or any(op in self.spent for op in ops):\n            raise ValueError("Double spend")\n\n        # Resolve every UTXO and all cheap semantic failures before reserving\n        # scarce crypto-validation work.  This prevents malformed junk from\n        # burning the public ingress budget while keeping acceptance semantics.\n        resolved = []\n        in_sum = 0\n        auth_work_units = 0\n        next_height = self.chain.tip.height + 1\n        auth_cost = {\n            SCHEME_ED25519: 1,\n            SCHEME_ML_DSA: 4,\n            SCHEME_HYBRID: 5,\n        }\n        for i, op in zip(inputs, ops):\n            u = self.chain.utxo.get(op)\n            if u is None:\n                raise ValueError("Input not found / unconfirmed")\n            if u["coinbase"] and self.chain.tip.height - u["height"] < COINBASE_MATURITY:\n                raise ValueError("Coinbase not mature")\n            if not canonical_input_valid(i):\n                raise ValueError("Bad signature")\n            try:\n                required_scheme = scheme_of_address(u["recipient"])\n            except ValueError as exc:\n                raise ValueError("Bad signature") from exc\n            supplied_scheme = _input_get(i, "scheme", "") or SCHEME_ED25519\n            if supplied_scheme != required_scheme:\n                raise ValueError("Bad signature")\n            auth_work_units += auth_cost[required_scheme]\n            resolved.append((i, u))\n            in_sum += u["amount"]\n\n        out_sum = 0\n        for o in tx.outputs:\n            if o.amount < DUST:\n                raise ValueError("Dust / non-positive output")\n            if not output_scheme_allowed(o.recipient, next_height):\n                raise ValueError("Forbidden output scheme")\n            out_sum += o.amount\n        if out_sum > in_sum:\n            raise ValueError("Outputs exceed inputs")\n\n        if work_gate is not None and not work_gate(auth_work_units):\n            raise ValueError("transaction validation work budget exceeded")\n\n        sh = tx.sighash()\n        for i, u in resolved:\n            if not verify_input(i, u, sh, next_height):\n                raise ValueError("Bad signature")\n\n        self.txs[tid] = tx\n        self.fees[tid] = in_sum - out_sum\n        self.tx_sizes[tid] = tx_bytes\n        self.total_bytes += tx_bytes\n        self.spent.update(ops)\n        return tid\n'''
rewrite("axven.py", old_mempool, new_mempool)

# P2P weighted transaction ingress budget. A maximum 1024-input hybrid relay
# costs 5120 units and fits exactly in a fresh per-host/global burst.
rewrite(
    "p2p.py",
    '''MAX_P2P_TX_INPUTS = 1024\nMAX_P2P_TX_OUTPUTS = 1024\nMAX_P2P_MESSAGE_TYPE_CHARS = 32\n''',
    '''MAX_P2P_TX_INPUTS = 1024\nMAX_P2P_TX_OUTPUTS = 1024\n# Public standalone TX relay can otherwise trigger unbounded Ed25519/ML-DSA\n# verification under the chain+mempool locks.  Work units are local ingress\n# policy only: Ed25519=1, ML-DSA=4, hybrid=5.\nINBOUND_TX_WORK_ED25519 = 1\nINBOUND_TX_WORK_ML_DSA = 4\nINBOUND_TX_WORK_HYBRID = 5\nINBOUND_TX_WORK_GLOBAL_RATE = 256.0\nINBOUND_TX_WORK_GLOBAL_BURST = MAX_P2P_TX_INPUTS * INBOUND_TX_WORK_HYBRID\nINBOUND_TX_WORK_PER_HOST_RATE = 64.0\nINBOUND_TX_WORK_PER_HOST_BURST = MAX_P2P_TX_INPUTS * INBOUND_TX_WORK_HYBRID\nMAX_INBOUND_TX_WORK_HOSTS = 1024\nMAX_P2P_MESSAGE_TYPE_CHARS = 32\n''',
)

limiter = '''\n\nclass _InboundTxWorkLimiter:\n    """Thread-safe weighted global + source-host TX crypto budget."""\n    def __init__(\n        self,\n        clock=time.monotonic,\n        global_rate=INBOUND_TX_WORK_GLOBAL_RATE,\n        global_burst=INBOUND_TX_WORK_GLOBAL_BURST,\n        per_host_rate=INBOUND_TX_WORK_PER_HOST_RATE,\n        per_host_burst=INBOUND_TX_WORK_PER_HOST_BURST,\n        max_hosts=MAX_INBOUND_TX_WORK_HOSTS,\n    ):\n        self._clock=clock\n        self._global_rate=float(global_rate)\n        self._global_burst=float(global_burst)\n        self._per_host_rate=float(per_host_rate)\n        self._per_host_burst=float(per_host_burst)\n        self._max_hosts=int(max_hosts)\n        if (\n            self._global_rate <= 0\n            or self._global_burst < 1\n            or self._per_host_rate <= 0\n            or self._per_host_burst < 1\n            or self._max_hosts < 1\n        ):\n            raise ValueError("invalid inbound transaction work budget")\n        now=float(self._clock())\n        self._global_tokens=self._global_burst\n        self._global_last=now\n        self._hosts=OrderedDict()\n        self._lock=threading.Lock()\n\n    @staticmethod\n    def _refill(tokens, last, now, rate, burst):\n        elapsed=max(0.0, now-last)\n        return min(burst, tokens + elapsed*rate)\n\n    def consume(self, host, cost):\n        if not isinstance(host,str) or not host or type(cost) is not int or cost < 1:\n            return False\n        now=float(self._clock())\n        with self._lock:\n            global_tokens=self._refill(\n                self._global_tokens, self._global_last, now,\n                self._global_rate, self._global_burst,\n            )\n            entry=self._hosts.get(host)\n            if entry is None:\n                host_tokens=self._per_host_burst\n                host_last=now\n            else:\n                host_tokens,host_last=entry\n                host_tokens=self._refill(\n                    host_tokens,host_last,now,\n                    self._per_host_rate,self._per_host_burst,\n                )\n            allowed=(global_tokens >= cost and host_tokens >= cost)\n            if allowed:\n                global_tokens-=cost\n                host_tokens-=cost\n            self._global_tokens=global_tokens\n            self._global_last=now\n            if entry is None and len(self._hosts) >= self._max_hosts:\n                self._hosts.popitem(last=False)\n            self._hosts[host]=(host_tokens,now)\n            self._hosts.move_to_end(host)\n            return allowed\n\n    def snapshot(self):\n        with self._lock:\n            return {\n                "global_tokens": self._global_tokens,\n                "hosts": len(self._hosts),\n            }\n'''
rewrite(
    "p2p.py",
    '''\n\ndef _reject_duplicate_json_keys(pairs):\n''',
    limiter + '''\n\ndef _reject_duplicate_json_keys(pairs):\n''',
)

rewrite(
    "p2p.py",
    '''    def handle(self,msg,block_work_gate=None):\n''',
    '''    def handle(self,msg,block_work_gate=None,tx_work_gate=None):\n''',
)
rewrite(
    "p2p.py",
    '''            tx=axven.Transaction.from_dict(raw_tx)\n            tid=self.mempool.add(tx)\n            return {"type":"accepted","kind":"tx","id":tid}\n''',
    '''            tx=axven.Transaction.from_dict(raw_tx)\n            if tx_work_gate is None:\n                tid=self.mempool.add(tx)\n            else:\n                tid=self.mempool.add(tx,work_gate=tx_work_gate)\n            return {"type":"accepted","kind":"tx","id":tid}\n''',
)
rewrite(
    "p2p.py",
    '''def serve_connection(sock,session:PeerSession,block_work_gate=None):\n''',
    '''def serve_connection(\n    sock,session:PeerSession,block_work_gate=None,tx_work_gate=None\n):\n''',
)
rewrite(
    "p2p.py",
    '''            reply=session.handle(msg,block_work_gate=block_work_gate)\n            if reply is not None: send_message(sock,reply)\n''',
    '''            if tx_work_gate is not None:\n                reply=session.handle(\n                    msg,\n                    block_work_gate=block_work_gate,\n                    tx_work_gate=tx_work_gate,\n                )\n            elif block_work_gate is not None:\n                reply=session.handle(msg,block_work_gate=block_work_gate)\n            else:\n                reply=session.handle(msg)\n            if reply is not None: send_message(sock,reply)\n''',
)
rewrite(
    "p2p.py",
    '''        self._block_work_limiter=_InboundBlockWorkLimiter()\n''',
    '''        self._block_work_limiter=_InboundBlockWorkLimiter()\n        self._tx_work_limiter=_InboundTxWorkLimiter()\n''',
)
rewrite(
    "p2p.py",
    '''                def worker(client=c,source_host=remote_host):\n                    gate=lambda: self._block_work_limiter.consume(source_host)\n                    try:\n                        serve_connection(\n                            client,self.session,block_work_gate=gate\n                        )\n''',
    '''                def worker(client=c,source_host=remote_host):\n                    block_gate=lambda: self._block_work_limiter.consume(source_host)\n                    tx_gate=lambda cost: self._tx_work_limiter.consume(\n                        source_host,cost\n                    )\n                    try:\n                        serve_connection(\n                            client,self.session,\n                            block_work_gate=block_gate,\n                            tx_work_gate=tx_gate,\n                        )\n''',
)

spec = r'''#!/usr/bin/env python3
"""SEC-119 bounds public standalone transaction signature-validation work."""
import inspect

import axven
import p2p


class FakeClock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def advance(self, seconds): self.now += seconds


def green(name, condition):
    assert condition, name
    print(f"[GREEN] {name}")


def synthetic_input(prev, scheme):
    if scheme == axven.SCHEME_ED25519:
        return axven.TxInput(prev, 0, signature="sig", public_key="pub")
    if scheme == axven.SCHEME_ML_DSA:
        return axven.TxInput(
            prev, 0, scheme=scheme, signature="sig", public_key="pub"
        )
    return axven.TxInput(
        prev, 0, scheme=scheme,
        ed_signature="es", ed_public_key="ep",
        ml_signature="ms", ml_public_key="mp",
    )


def inject_utxo(chain, prev, recipient, amount=100_000):
    chain.utxo[axven.outpoint(prev, 0)] = {
        "amount": amount,
        "recipient": recipient,
        "coinbase": False,
        "height": 0,
    }


def main():
    checks = []
    def ok(name, condition):
        green(name, condition); checks.append(name)

    max_cost = p2p.MAX_P2P_TX_INPUTS * p2p.INBOUND_TX_WORK_HYBRID
    ok(
        "weighted inbound TX budgets pinned and maximum relay fits burst",
        p2p.INBOUND_TX_WORK_ED25519 == 1
        and p2p.INBOUND_TX_WORK_ML_DSA == 4
        and p2p.INBOUND_TX_WORK_HYBRID == 5
        and p2p.INBOUND_TX_WORK_PER_HOST_BURST >= max_cost
        and p2p.INBOUND_TX_WORK_GLOBAL_BURST >= max_cost
        and p2p.MAX_INBOUND_TX_WORK_HOSTS == 1024,
    )

    clock = FakeClock()
    limiter = p2p._InboundTxWorkLimiter(
        clock=clock, global_rate=10, global_burst=10,
        per_host_rate=5, per_host_burst=10, max_hosts=3,
    )
    ok("single source weighted burst is bounded", limiter.consume("a", 6) and not limiter.consume("a", 5))
    clock.advance(1.0)
    ok("single source weighted budget refills", limiter.consume("a", 5))

    clock2 = FakeClock()
    distributed = p2p._InboundTxWorkLimiter(
        clock=clock2, global_rate=1, global_burst=6,
        per_host_rate=10, per_host_burst=6, max_hosts=8,
    )
    ok(
        "distributed sources remain globally bounded",
        distributed.consume("a", 3)
        and distributed.consume("b", 3)
        and not distributed.consume("c", 1),
    )
    for host in ("d", "e", "f", "g"):
        distributed.consume(host, 1)
    ok("TX limiter source memory is independently bounded", distributed.snapshot()["hosts"] <= 8)

    # Cheap missing-input rejection must not consume the gate.
    chain = axven.Blockchain(); mp = axven.Mempool(chain)
    missing = axven.Transaction(
        [axven.TxInput("11" * 32, 0, signature="sig", public_key="pub")],
        [axven.TxOutput(1, "N" + "1" * 40)],
    )
    gate_calls = []
    try: mp.add(missing, work_gate=lambda cost: gate_calls.append(cost) or True)
    except ValueError as exc: missing_rejected = "Input not found" in str(exc)
    else: missing_rejected = False
    ok("missing-input junk consumes no crypto budget", missing_rejected and gate_calls == [])

    # Cheap output failure likewise stays ahead of the gate.
    chain2 = axven.Blockchain(); mp2 = axven.Mempool(chain2)
    prev2 = "22" * 32
    inject_utxo(chain2, prev2, "N" + "2" * 40)
    dust = axven.Transaction(
        [synthetic_input(prev2, axven.SCHEME_ED25519)],
        [axven.TxOutput(0, "N" + "3" * 40)],
    )
    dust_calls = []
    try: mp2.add(dust, work_gate=lambda cost: dust_calls.append(cost) or True)
    except ValueError as exc: dust_rejected = "Dust" in str(exc)
    else: dust_rejected = False
    ok("cheap output failure consumes no crypto budget", dust_rejected and dust_calls == [])

    # Cost is derived from resolved UTXO schemes, not attacker-selected size.
    chain3 = axven.Blockchain(); mp3 = axven.Mempool(chain3)
    prevs = ["31" * 32, "32" * 32, "33" * 32]
    recipients = ["N" + "a" * 40, "M" + "b" * 40, "H" + "c" * 40]
    schemes = [axven.SCHEME_ED25519, axven.SCHEME_ML_DSA, axven.SCHEME_HYBRID]
    for prev, recipient in zip(prevs, recipients): inject_utxo(chain3, prev, recipient)
    weighted = axven.Transaction(
        [synthetic_input(prev, scheme) for prev, scheme in zip(prevs, schemes)],
        [axven.TxOutput(1, "N" + "d" * 40)],
    )
    captured = []
    original_verify = axven.verify_input
    axven.verify_input = lambda *args, **kwargs: True
    try:
        mp3.add(weighted, work_gate=lambda cost: captured.append(cost) or True)
    finally:
        axven.verify_input = original_verify
    ok("resolved Ed25519 ML-DSA and hybrid inputs are weighted exactly", captured == [10])

    # Exhaustion occurs before the first cryptographic verification.
    chain4 = axven.Blockchain(); mp4 = axven.Mempool(chain4)
    prev4 = "44" * 32
    inject_utxo(chain4, prev4, "N" + "4" * 40)
    candidate = axven.Transaction(
        [synthetic_input(prev4, axven.SCHEME_ED25519)],
        [axven.TxOutput(90_000, "N" + "5" * 40)],
    )
    verify_calls = []
    axven.verify_input = lambda *args, **kwargs: verify_calls.append(1) or True
    try:
        try: mp4.add(candidate, work_gate=lambda cost: False)
        except ValueError as exc: budget_rejected = "work budget exceeded" in str(exc)
        else: budget_rejected = False
    finally:
        axven.verify_input = original_verify
    ok("exhausted TX budget stops before signature verification", budget_rejected and verify_calls == [])

    # Healthy admission remains identical when budget is available.
    chain5 = axven.Blockchain(); mp5 = axven.Mempool(chain5); wallet = axven.Wallet()
    prev5 = "55" * 32
    inject_utxo(chain5, prev5, wallet.address)
    unsigned = axven.Transaction(
        [axven.TxInput(prev5, 0)],
        [axven.TxOutput(90_000, wallet.address)],
    )
    signed = axven.Transaction([wallet.sign_input(unsigned, 0)], unsigned.outputs)
    healthy_cost = []
    tid = mp5.add(signed, work_gate=lambda cost: healthy_cost.append(cost) or True)
    ok("valid transaction is admitted when crypto budget is available", tid in mp5.txs and healthy_cost == [1])

    # P2P uses the gate, while the legacy/unmetered mempool API stays compatible.
    chain6 = axven.Blockchain(); mp6 = axven.Mempool(chain6); wallet6 = axven.Wallet()
    prev6 = "66" * 32
    inject_utxo(chain6, prev6, wallet6.address)
    u6 = axven.Transaction([axven.TxInput(prev6, 0)], [axven.TxOutput(90_000, wallet6.address)])
    s6 = axven.Transaction([wallet6.sign_input(u6, 0)], u6.outputs)
    msg = {"type": "tx", "tx": s6.to_dict()}
    try:
        p2p.PeerSession(chain6, mp6).handle(msg, tx_work_gate=lambda cost: False)
    except ValueError as exc:
        peer_rejected = "work budget exceeded" in str(exc)
    else:
        peer_rejected = False
    ok("PeerSession enforces inbound TX crypto-work gate", peer_rejected and not mp6.txs)

    class LegacyMempool:
        def __init__(self): self.seen = []
        def add(self, tx): self.seen.append(tx); return tx.txid()
    legacy = LegacyMempool()
    reply = p2p.PeerSession(object(), legacy).handle(msg)
    ok(
        "unmetered session preserves legacy mempool add call shape",
        reply["type"] == "accepted" and len(legacy.seen) == 1,
    )

    # Direct/local mempool admission remains unthrottled by default.
    chain7 = axven.Blockchain(); mp7 = axven.Mempool(chain7); wallet7 = axven.Wallet()
    prev7 = "77" * 32
    inject_utxo(chain7, prev7, wallet7.address)
    u7 = axven.Transaction([axven.TxInput(prev7, 0)], [axven.TxOutput(90_000, wallet7.address)])
    s7 = axven.Transaction([wallet7.sign_input(u7, 0)], u7.outputs)
    mp7.add(s7)
    ok("local direct mempool admission remains unthrottled", s7.txid() in mp7.txs)

    mempool_src = inspect.getsource(axven.Mempool._add_locked)
    session_src = inspect.getsource(p2p.PeerSession.handle)
    serve_src = inspect.getsource(p2p.serve_connection)
    server_src = inspect.getsource(p2p.NodeServer.start)
    sync_src = inspect.getsource(p2p.sync_once)
    ok(
        "production wiring meters only expensive public standalone TX validation",
        'work_gate is not None and not work_gate(auth_work_units)' in mempool_src
        and mempool_src.index('Input not found / unconfirmed') < mempool_src.index('work_gate is not None and not work_gate(auth_work_units)')
        and mempool_src.index('Dust / non-positive output') < mempool_src.index('work_gate is not None and not work_gate(auth_work_units)')
        and mempool_src.index('work_gate is not None and not work_gate(auth_work_units)') < mempool_src.index('verify_input(i, u, sh, next_height)')
        and 'tx_work_gate=tx_work_gate' in serve_src
        and '_tx_work_limiter.consume' in server_src
        and 'work_gate=tx_work_gate' in session_src
        and 'tx_work_gate' not in sync_src,
    )

    print(f"SEC-119 inbound TX crypto-work budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
Path("security_sec119_p2p_inbound_tx_crypto_work_spec.py").write_text(spec, encoding="utf-8", newline="\n")

# Refresh release manifest only from LF-normalized committed bytes.
manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in (
    "axven.py",
    "p2p.py",
    "security_sec119_p2p_inbound_tx_crypto_work_spec.py",
):
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
print("SEC-119 patch staged with LF-normalized manifest hashes")
