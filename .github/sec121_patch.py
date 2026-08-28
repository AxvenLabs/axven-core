#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_lf(path: Path) -> str:
    return path.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")


def write_lf(path: Path, text: str) -> None:
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"SEC-121 patch anchor {label!r}: expected 1 match, got {count}")
    return text.replace(old, new, 1)


p2p_path = ROOT / "p2p.py"
p2p = read_lf(p2p_path)

p2p = replace_once(
    p2p,
    "MAX_INBOUND_BLOCK_SIGNATURE_WORK_HOSTS = 1024\nMAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "MAX_INBOUND_BLOCK_SIGNATURE_WORK_HOSTS = 1024\n"
    "# Configured outbound peers are still untrusted network sources.  Give a\n"
    "# healthy peer one full sync batch of fresh block-validation work, then\n"
    "# refill above normal chain production without allowing the legacy\n"
    "# max_rounds reconnect loop to become an unbounded CPU amplifier.\n"
    "OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_RATE = 8.0\n"
    "OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_BURST = MAX_SYNC_BLOCKS * 2\n"
    "OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_RATE = 2.0\n"
    "OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_BURST = MAX_SYNC_BLOCKS\n"
    "MAX_OUTBOUND_SYNC_BLOCK_WORK_HOSTS = 1024\n"
    "# One consensus-max valid signed block must always fit a fresh peer burst;\n"
    "# repeated expensive blocks are then rate-limited across reconnects.\n"
    "OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_RATE = 4096.0\n"
    "OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK * 2\n"
    "OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_RATE = 1024.0\n"
    "OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK\n"
    "MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS = 1024\n"
    "MAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "outbound constants",
)

p2p = replace_once(
    p2p,
    "class ProtocolError(ValueError): pass\n",
    "class ProtocolError(ValueError): pass\n\n"
    "def _work_budget_status(status):\n"
    "    if not isinstance(status,str):\n"
    "        return False\n"
    "    return (\n"
    "        status == \"validation work budget exceeded\"\n"
    "        or status.startswith(\"Signature work budget exceeded at \" )\n"
    "        or status.startswith(\"reorg aborted: Signature work budget exceeded at \" )\n"
    "    )\n",
    "budget status helper",
)

p2p = replace_once(
    p2p,
    "\n\ndef _reject_duplicate_json_keys(pairs):\n",
    "\n\nclass _OutboundSyncBlockWorkLimiter(_InboundBlockWorkLimiter):\n"
    "    \"\"\"Persistent configured-peer block-validation work budget.\"\"\"\n"
    "    def __init__(\n"
    "        self,\n"
    "        clock=time.monotonic,\n"
    "        global_rate=OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_RATE,\n"
    "        global_burst=OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_BURST,\n"
    "        per_host_rate=OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_RATE,\n"
    "        per_host_burst=OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_BURST,\n"
    "        max_hosts=MAX_OUTBOUND_SYNC_BLOCK_WORK_HOSTS,\n"
    "    ):\n"
    "        super().__init__(\n"
    "            clock=clock, global_rate=global_rate, global_burst=global_burst,\n"
    "            per_host_rate=per_host_rate, per_host_burst=per_host_burst,\n"
    "            max_hosts=max_hosts,\n"
    "        )\n\n\n"
    "class _OutboundSyncBlockSignatureWorkLimiter(_InboundBlockSignatureWorkLimiter):\n"
    "    \"\"\"Persistent configured-peer weighted block-signature budget.\"\"\"\n"
    "    def __init__(\n"
    "        self,\n"
    "        clock=time.monotonic,\n"
    "        global_rate=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_RATE,\n"
    "        global_burst=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_BURST,\n"
    "        per_host_rate=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_RATE,\n"
    "        per_host_burst=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_BURST,\n"
    "        max_hosts=MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS,\n"
    "    ):\n"
    "        super().__init__(\n"
    "            clock=clock, global_rate=global_rate, global_burst=global_burst,\n"
    "            per_host_rate=per_host_rate, per_host_burst=per_host_burst,\n"
    "            max_hosts=max_hosts,\n"
    "        )\n"
    "\n\ndef _reject_duplicate_json_keys(pairs):\n",
    "outbound limiter classes",
)

p2p = replace_once(
    p2p,
    "    def handle(\n"
    "        self, msg, block_work_gate=None, tx_work_gate=None,\n"
    "        block_signature_work_gate=None,\n"
    "    ):\n",
    "    def handle(\n"
    "        self, msg, block_work_gate=None, tx_work_gate=None,\n"
    "        block_signature_work_gate=None, stop_on_work_budget=False,\n"
    "    ):\n",
    "PeerSession.handle signature",
)

p2p = replace_once(
    p2p,
    "                if ok or status==\"duplicate\": accepted+=1\n"
    "                elif status==\"orphan\": continue\n"
    "                else: raise ProtocolError(f\"sync block rejected: {status}\")\n"
    "            return {\"type\":\"accepted\",\"kind\":\"blocks\",\"count\":accepted}\n",
    "                if ok or status==\"duplicate\": accepted+=1\n"
    "                elif status==\"orphan\": continue\n"
    "                elif stop_on_work_budget and _work_budget_status(status):\n"
    "                    return {\n"
    "                        \"type\":\"accepted\", \"kind\":\"blocks\",\n"
    "                        \"count\":accepted, \"work_budget_exhausted\":True,\n"
    "                    }\n"
    "                else: raise ProtocolError(f\"sync block rejected: {status}\")\n"
    "            return {\"type\":\"accepted\",\"kind\":\"blocks\",\"count\":accepted}\n",
    "partial batch budget handling",
)

p2p = replace_once(
    p2p,
    "def sync_to_peer(address,session,limit=128,max_rounds=100):\n"
    "    \"\"\"Reconnect-friendly catch-up until the peer returns no more blocks.\"\"\"\n"
    "    total=0\n"
    "    sock=connect(address)\n"
    "    try:\n"
    "        for _ in range(max_rounds):\n"
    "            reply=request(sock,{\"type\":\"get_blocks\",\"locator\":session.locator(),\"limit\":limit})\n"
    "            if reply.get(\"type\")!=\"blocks\":raise ProtocolError(\"expected blocks\")\n"
    "            blocks=reply.get(\"blocks\")\n"
    "            if not isinstance(blocks,list):raise ProtocolError(\"blocks must be list\")\n"
    "            if not blocks:break\n"
    "            result=session.handle(reply); total+=result[\"count\"]\n"
    "        return total\n"
    "    finally:\n"
    "        try:sock.close()\n"
    "        except OSError:pass\n",
    "def sync_to_peer(\n"
    "    address, session, limit=128, max_rounds=100,\n"
    "    block_work_gate=None, block_signature_work_gate=None,\n"
    "):\n"
    "    \"\"\"Reconnect-friendly catch-up until empty reply or local work budget.\"\"\"\n"
    "    total=0\n"
    "    sock=connect(address)\n"
    "    try:\n"
    "        for _ in range(max_rounds):\n"
    "            reply=request(sock,{\"type\":\"get_blocks\",\"locator\":session.locator(),\"limit\":limit})\n"
    "            if reply.get(\"type\")!=\"blocks\":raise ProtocolError(\"expected blocks\")\n"
    "            blocks=reply.get(\"blocks\")\n"
    "            if not isinstance(blocks,list):raise ProtocolError(\"blocks must be list\")\n"
    "            if not blocks:break\n"
    "            if block_work_gate is None and block_signature_work_gate is None:\n"
    "                result=session.handle(reply)\n"
    "            else:\n"
    "                result=session.handle(\n"
    "                    reply,\n"
    "                    block_work_gate=block_work_gate,\n"
    "                    block_signature_work_gate=block_signature_work_gate,\n"
    "                    stop_on_work_budget=True,\n"
    "                )\n"
    "            total+=result[\"count\"]\n"
    "            if result.get(\"work_budget_exhausted\"):\n"
    "                break\n"
    "        return total\n"
    "    finally:\n"
    "        try:sock.close()\n"
    "        except OSError:pass\n",
    "sync_to_peer gated partial sync",
)

write_lf(p2p_path, p2p)

core_path = ROOT / "core.py"
core = read_lf(core_path)
core = replace_once(
    core,
    "        self._peer_lock = threading.RLock()\n"
    "        self.outbound_peers = []\n",
    "        self._peer_lock = threading.RLock()\n"
    "        # Persist automatic configured-peer work budgets on the core, not\n"
    "        # on a socket.  Reconnecting therefore cannot mint a fresh burst.\n"
    "        self._outbound_sync_block_work_limiter = (\n"
    "            p2p._OutboundSyncBlockWorkLimiter()\n"
    "        )\n"
    "        self._outbound_sync_block_signature_work_limiter = (\n"
    "            p2p._OutboundSyncBlockSignatureWorkLimiter()\n"
    "        )\n"
    "        self.outbound_peers = []\n",
    "AxvenCore persistent outbound limiters",
)

core = replace_once(
    core,
    "        try:\n"
    "            accepted=p2p.sync_to_peer(\n"
    "                addr,p2p.PeerSession(self.chain,self.mempool),limit=128\n"
    "            )\n"
    "        except Exception as e:\n",
    "        try:\n"
    "            source_host=addr[0]\n"
    "            block_gate=lambda: (\n"
    "                self._outbound_sync_block_work_limiter.consume(source_host)\n"
    "            )\n"
    "            signature_gate=lambda cost: (\n"
    "                self._outbound_sync_block_signature_work_limiter.consume(\n"
    "                    source_host,cost\n"
    "                )\n"
    "            )\n"
    "            accepted=p2p.sync_to_peer(\n"
    "                addr,p2p.PeerSession(self.chain,self.mempool),limit=128,\n"
    "                block_work_gate=block_gate,\n"
    "                block_signature_work_gate=signature_gate,\n"
    "            )\n"
    "        except Exception as e:\n",
    "configured peer gated sync",
)
write_lf(core_path, core)

spec = r'''#!/usr/bin/env python3
"""SEC-121 bound configured/outbound peer sync work across reconnects."""

import inspect
import axven
import core as core_module
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
    target = axven.Blockchain()
    for block in source.blocks[1:height + 1]:
        ok, status = target.add_block(block)
        assert ok and status == "extended"
    return target


def signed_spend_block(chain, wallet):
    recipient = axven.Wallet().address
    txid, index, amount = chain.spendable(wallet.address)[0]
    tx = axven.Transaction(
        [axven.TxInput(txid, index)],
        [axven.TxOutput(amount - 1, recipient)],
    )
    tx.inputs[0] = wallet.sign_input(tx, 0)
    mp = axven.Mempool(chain)
    mp.add(tx)
    return chain.build_candidate(wallet.address, mp)


def main():
    checks = []
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "outbound block sync budget allows one full batch but bounds legacy rounds",
        p2p.OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_BURST == p2p.MAX_SYNC_BLOCKS
        and p2p.OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_BURST >= 2 * p2p.MAX_SYNC_BLOCKS
        and 0 < p2p.OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_RATE < p2p.MAX_SYNC_BLOCKS,
    )
    green(
        "outbound signature burst admits one consensus-max valid signed block",
        p2p.OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_BURST
            == p2p.MAX_VALID_BLOCK_SIGNATURE_WORK
        and p2p.OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_BURST
            >= 2 * p2p.MAX_VALID_BLOCK_SIGNATURE_WORK,
    )

    clock = FakeClock()
    limiter = p2p._OutboundSyncBlockWorkLimiter(
        clock=clock, global_rate=1, global_burst=2,
        per_host_rate=1, per_host_burst=2, max_hosts=2,
    )
    green(
        "same outbound source cannot mint fresh work by reconnecting",
        limiter.consume("192.0.2.1")
        and limiter.consume("192.0.2.1")
        and not limiter.consume("192.0.2.1"),
    )
    clock.advance(1.0)
    green(
        "outbound block budget refills without peer reconfiguration",
        limiter.consume("192.0.2.1"),
    )

    sig_clock = FakeClock()
    sig_limiter = p2p._OutboundSyncBlockSignatureWorkLimiter(
        clock=sig_clock, global_rate=2, global_burst=5,
        per_host_rate=1, per_host_burst=3, max_hosts=2,
    )
    green(
        "outbound weighted signature budget persists across reconnect attempts",
        sig_limiter.consume("198.51.100.1", 3)
        and not sig_limiter.consume("198.51.100.1", 1),
    )

    miner = axven.Wallet()
    source = mine_chain(5, miner)
    target = axven.Blockchain()
    server = p2p.NodeServer(source, None, host="127.0.0.1", port=0).start()
    try:
        net_clock = FakeClock()
        net_limiter = p2p._OutboundSyncBlockWorkLimiter(
            clock=net_clock, global_rate=1, global_burst=2,
            per_host_rate=1, per_host_burst=2, max_hosts=2,
        )
        gate = lambda: net_limiter.consume("127.0.0.1")
        accepted = p2p.sync_to_peer(
            server.address, p2p.PeerSession(target, None),
            limit=5, max_rounds=10, block_work_gate=gate,
        )
        green(
            "gated outbound sync stops as successful partial progress at budget edge",
            accepted == 2 and target.tip.height == 2 and target.validate(),
        )
        accepted_again = p2p.sync_to_peer(
            server.address, p2p.PeerSession(target, None),
            limit=5, max_rounds=10, block_work_gate=gate,
        )
        green(
            "socket reconnect does not reset exhausted outbound sync budget",
            accepted_again == 0 and target.tip.height == 2 and target.validate(),
        )
        net_clock.advance(1.0)
        accepted_refill = p2p.sync_to_peer(
            server.address, p2p.PeerSession(target, None),
            limit=5, max_rounds=10, block_work_gate=gate,
        )
        green(
            "refilled configured-peer budget resumes from the retained locator",
            accepted_refill == 1 and target.tip.height == 3 and target.validate(),
        )
        legacy_target = axven.Blockchain()
        legacy_accepted = p2p.sync_to_peer(
            server.address, p2p.PeerSession(legacy_target, None),
            limit=5, max_rounds=10,
        )
        green(
            "legacy unmetered sync_to_peer behavior remains compatible",
            legacy_accepted == 5 and legacy_target.tip.height == 5
            and legacy_target.validate(),
        )
    finally:
        server.stop()

    mature = mine_chain(axven.COINBASE_MATURITY + 1, miner)
    spend_block = signed_spend_block(mature, miner)
    strict_target = replay_prefix(mature, mature.tip.height)
    strict_session = p2p.PeerSession(strict_target, None)
    partial = strict_session.handle(
        {"type": "blocks", "blocks": [spend_block.to_dict()]},
        block_work_gate=lambda: True,
        block_signature_work_gate=lambda _cost: False,
        stop_on_work_budget=True,
    )
    green(
        "signature budget exhaustion is graceful only for explicit outbound partial sync",
        partial.get("work_budget_exhausted") is True
        and partial["count"] == 0
        and strict_target.tip.height == mature.tip.height,
    )

    strict_target2 = replay_prefix(mature, mature.tip.height)
    try:
        p2p.PeerSession(strict_target2, None).handle(
            {"type": "blocks", "blocks": [spend_block.to_dict()]},
            block_work_gate=lambda: True,
            block_signature_work_gate=lambda _cost: False,
        )
        strict_rejected = False
    except p2p.ProtocolError as exc:
        strict_rejected = "Signature work budget exceeded" in str(exc)
    green(
        "ordinary inbound block-batch semantics remain strict on exhausted budget",
        strict_rejected and strict_target2.tip.height == mature.tip.height,
    )

    configured = core_module.AxvenCore()
    addr = configured.add_outbound_peer(("example.test", 18444))
    fake_clock = FakeClock()
    configured._outbound_sync_block_work_limiter = p2p._OutboundSyncBlockWorkLimiter(
        clock=fake_clock, global_rate=1, global_burst=2,
        per_host_rate=1, per_host_burst=2, max_hosts=2,
    )
    configured._outbound_sync_block_signature_work_limiter = (
        p2p._OutboundSyncBlockSignatureWorkLimiter(
            clock=fake_clock, global_rate=1, global_burst=2,
            per_host_rate=1, per_host_burst=2, max_hosts=2,
        )
    )
    block_limiter_id = id(configured._outbound_sync_block_work_limiter)
    sig_limiter_id = id(configured._outbound_sync_block_signature_work_limiter)
    calls = []
    original_sync = p2p.sync_to_peer
    def fake_sync(address, session, **kwargs):
        block_gate = kwargs["block_work_gate"]
        sig_gate = kwargs["block_signature_work_gate"]
        got_block = block_gate()
        got_sig = sig_gate(1)
        calls.append((address, got_block, got_sig))
        return int(got_block and got_sig)
    p2p.sync_to_peer = fake_sync
    try:
        first = configured.sync_outbound_peer(addr)
        second = configured.sync_outbound_peer(addr)
        third = configured.sync_outbound_peer(addr)
    finally:
        p2p.sync_to_peer = original_sync
    green(
        "AxvenCore keeps configured-peer limiter instances across sync calls",
        id(configured._outbound_sync_block_work_limiter) == block_limiter_id
        and id(configured._outbound_sync_block_signature_work_limiter) == sig_limiter_id
        and [row[1:] for row in calls] == [(True, True), (True, True), (False, False)],
    )
    green(
        "budget-limited configured sync is healthy rather than peer failure",
        first["ok"] and second["ok"] and third["ok"]
        and third["accepted"] == 0
        and configured.peer_last_error.get(addr) is None
        and configured.peer_consecutive_failures.get(addr) == 0,
    )

    sync_src = inspect.getsource(p2p.sync_to_peer)
    handle_src = inspect.getsource(p2p.PeerSession.handle)
    core_sync_src = inspect.getsource(core_module.AxvenCore.sync_outbound_peer)
    manual_sync_src = inspect.getsource(core_module.AxvenCore.sync_peer)
    green(
        "production wiring meters only automatic configured-peer catch-up",
        "stop_on_work_budget=True" in sync_src
        and "work_budget_exhausted" in sync_src
        and "_work_budget_status(status)" in handle_src
        and "_outbound_sync_block_work_limiter.consume(source_host)" in core_sync_src
        and "_outbound_sync_block_signature_work_limiter.consume" in core_sync_src
        and "block_work_gate=block_gate" in core_sync_src
        and "block_signature_work_gate=signature_gate" in core_sync_src
        and "block_work_gate" not in manual_sync_src
        and "block_signature_work_gate" not in manual_sync_src,
    )

    print(f"SEC-121 outbound sync work budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = ROOT / "security_sec121_outbound_sync_work_budget_spec.py"
write_lf(spec_path, spec)

manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(read_lf(manifest_path))
for rel in ("core.py", "p2p.py", "security_sec121_outbound_sync_work_budget_spec.py"):
    raw = (ROOT / rel).read_bytes().replace(b"\r\n", b"\n")
    manifest["files"][rel] = {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
write_lf(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")

print("SEC-121 patch helper applied")