#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json
import textwrap

CORE = Path("core.py")
DAEMON = Path("axven_core.py")
SPEC = Path("security_sec101_peer_lifecycle_atomicity_spec.py")
MANIFEST = Path("release_manifest.json")


def replace_method(text, name, next_name, replacement):
    start = text.index(f"    def {name}(")
    end = text.index(f"    def {next_name}(", start)
    return text[:start] + replacement.rstrip() + "\n\n" + text[end:]


def wrap_method(text, name, next_name, first_body_anchor):
    start = text.index(f"    def {name}(")
    end = text.index(f"    def {next_name}(", start)
    segment = text[start:end]
    pos = segment.index(first_body_anchor)
    prefix = segment[:pos]
    body = segment[pos:]
    wrapped = prefix + "        with _peer_guard(self):\n" + textwrap.indent(body, "    ")
    return text[:start] + wrapped + text[end:]


text = CORE.read_text(encoding="utf-8")
text = text.replace(
    "import math\nfrom datetime import datetime, timezone\n",
    "import math\nimport threading\nfrom datetime import datetime, timezone\n",
    1,
)
text = text.replace(
    '''def _mempool_guard(mempool):\n    lock=getattr(mempool,"_lock",None)\n    return lock if lock is not None else nullcontext()\n\n\nclass AxvenCore:\n''',
    '''def _mempool_guard(mempool):\n    lock=getattr(mempool,"_lock",None)\n    return lock if lock is not None else nullcontext()\n\ndef _peer_guard(core):\n    lock=getattr(core,"_peer_lock",None)\n    return lock if lock is not None else nullcontext()\n\n\nclass AxvenCore:\n''',
    1,
)
text = text.replace(
    "        self.p2p_server = None\n        self.outbound_peers = []\n",
    "        self.p2p_server = None\n        self._peer_lock = threading.RLock()\n        self.outbound_peers = []\n",
    1,
)

# Persistence callbacks must see immutable snapshots while membership mutation is serialized.
text = text.replace(
    "                self.peer_persist_callback(self.outbound_peers)\n",
    "                self.peer_persist_callback(list(self.outbound_peers))\n",
)

# Add a defensive membership snapshot API for the daemon and threaded callers.
add_anchor = "    def add_outbound_peer(self, peer):\n"
if add_anchor not in text:
    raise SystemExit("SEC-101 add_outbound_peer anchor not found")
text = text.replace(
    add_anchor,
    '''    def outbound_peer_addresses(self):\n        with _peer_guard(self):\n            return list(self.outbound_peers)\n\n    def add_outbound_peer(self, peer):\n''',
    1,
)

# Serialize membership, persistence, health transition publication and retry state.
text = wrap_method(text, "add_outbound_peer", "remove_outbound_peer", "        addr=self._parse_peer(peer)\n")
text = wrap_method(text, "remove_outbound_peer", "peer_health_state", "        addr=self._parse_peer(peer)\n")
text = wrap_method(text, "record_peer_health_transition", "outbound_peer_status", "        addr=self._parse_peer(peer)\n")
text = wrap_method(text, "outbound_peer_status", "peer_health_summary", "        return [\n")
text = wrap_method(text, "set_peer_retry_schedule", "clear_peer_retry_schedule", "        addr=self._parse_peer(peer)\n")
text = wrap_method(text, "clear_peer_retry_schedule", "peer_retry_delay", "        addr=self._parse_peer(peer)\n")
text = wrap_method(text, "peer_retry_delay", "sync_outbound_peer", "        addr=self._parse_peer(peer)\n")

sync_replacement = '''    def sync_outbound_peer(self, peer):
        """Synchronize one configured outbound peer and update its health."""
        addr=self._parse_peer(peer)
        try:
            accepted=p2p.sync_to_peer(
                addr,p2p.PeerSession(self.chain,self.mempool),limit=128
            )
        except Exception as e:
            error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error
                    self.peer_consecutive_failures[addr]=self.peer_consecutive_failures.get(addr,0)+1
                    self.peer_last_failure_at[addr]=self._peer_health_timestamp()
                    self.record_peer_health_transition(addr)
            return {"peer":f"{addr[0]}:{addr[1]}","ok":False,
                    "error":error}

        with _peer_guard(self):
            if addr in self.outbound_peers:
                self.peer_last_error[addr]=None
                self.peer_sync_successes[addr]=self.peer_sync_successes.get(addr,0)+1
                self.peer_consecutive_failures[addr]=0
                self.peer_last_success_at[addr]=self._peer_health_timestamp()
                self.record_peer_health_transition(addr)
        return {"peer":f"{addr[0]}:{addr[1]}","ok":True,
                "accepted":accepted}'''
text = replace_method(text, "sync_outbound_peer", "sync_outbound_peers", sync_replacement)

sync_all_replacement = '''    def sync_outbound_peers(self):
        return [
            self.sync_outbound_peer(addr)
            for addr in self.outbound_peer_addresses()
        ]'''
text = replace_method(text, "sync_outbound_peers", "_propagate_block_outbound", sync_all_replacement)

block_replacement = '''    def _propagate_block_outbound(self, block):
        for addr in self.outbound_peer_addresses():
            try:
                p2p.propagate_block(addr,block)
                error=None
            except Exception as e:
                error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error'''
text = replace_method(text, "_propagate_block_outbound", "_propagate_tx_outbound", block_replacement)

tx_replacement = '''    def _propagate_tx_outbound(self, tx):
        for addr in self.outbound_peer_addresses():
            try:
                p2p.propagate_tx(addr,tx)
                error=None
            except Exception as e:
                error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error'''
text = replace_method(text, "_propagate_tx_outbound", "request_shutdown", tx_replacement)

with CORE.open("w", encoding="utf-8", newline="\n") as f:
    f.write(text)

# The retry daemon must use defensive snapshots and must not recreate retry state
# after a peer is removed while a network sync is in flight.
daemon = DAEMON.read_text(encoding="utf-8")
daemon = daemon.replace("for addr in core.outbound_peers", "for addr in core.outbound_peer_addresses()")
daemon = daemon.replace("configured=set(core.outbound_peers)", "configured=set(core.outbound_peer_addresses())")
daemon = daemon.replace("for addr in list(core.outbound_peers)", "for addr in core.outbound_peer_addresses()")
retry_anchor = '''                    core.sync_outbound_peer(addr)\n\n                    retry_delay=core.peer_retry_delay(\n'''
retry_replacement = '''                    core.sync_outbound_peer(addr)\n\n                    if addr not in set(core.outbound_peer_addresses()):\n                        peer_next_sync.pop(addr,None)\n                        continue\n\n                    retry_delay=core.peer_retry_delay(\n'''
if retry_anchor not in daemon:
    raise SystemExit("SEC-101 daemon retry anchor not found")
daemon = daemon.replace(retry_anchor, retry_replacement, 1)
with DAEMON.open("w", encoding="utf-8", newline="\n") as f:
    f.write(daemon)

spec = '''#!/usr/bin/env python3
"""SEC-101 outbound peer lifecycle concurrency contract."""

import threading
import time

import p2p
from core import AxvenCore


class FakeTx:
    def to_dict(self):
        return {"inputs": [], "outputs": []}

    def txid(self):
        return "11" * 32


def main():
    checks = 0

    # Concurrent membership changes must not run persistence callbacks together.
    core = AxvenCore()
    entered = threading.Event()
    release = threading.Event()
    overlap = threading.Event()
    counter_lock = threading.Lock()
    active = [0]

    def persist(_peers):
        with counter_lock:
            active[0] += 1
            if active[0] > 1:
                overlap.set()
        entered.set()
        release.wait(1.0)
        with counter_lock:
            active[0] -= 1

    core.peer_persist_callback = persist
    first = ("127.0.0.1", 19101)
    second = ("127.0.0.1", 19102)
    t1 = threading.Thread(target=lambda: core.add_outbound_peer(first), daemon=True)
    t2 = threading.Thread(target=lambda: core.add_outbound_peer(second), daemon=True)
    t1.start()
    assert entered.wait(1.0), "first persistence callback did not start"
    t2.start()
    time.sleep(0.15)
    release.set()
    t1.join(2.0); t2.join(2.0)
    assert not overlap.is_set(), "peer persistence callbacks overlapped"
    assert set(core.outbound_peer_addresses()) == {first, second}
    checks += 1
    print("[GREEN] peer membership persistence serialized")

    # A propagation finishing after removal must not recreate health state.
    core = AxvenCore()
    peer = ("127.0.0.1", 19103)
    core.add_outbound_peer(peer)
    entered = threading.Event(); release = threading.Event()
    original_propagate_tx = p2p.propagate_tx

    def blocked_propagate(_addr, _tx):
        entered.set()
        release.wait(1.0)
        raise ConnectionRefusedError("late propagation failure")

    p2p.propagate_tx = blocked_propagate
    try:
        worker = threading.Thread(
            target=lambda: core._propagate_tx_outbound(FakeTx()), daemon=True
        )
        worker.start()
        assert entered.wait(1.0), "propagation did not start"
        core.remove_outbound_peer(peer)
        release.set(); worker.join(2.0)
        assert peer not in core.peer_last_error, "removed peer health state recreated"
    finally:
        p2p.propagate_tx = original_propagate_tx
    checks += 1
    print("[GREEN] late propagation cannot recreate removed peer state")

    # The same invariant applies to a sync completing after removal.
    core = AxvenCore()
    peer = ("127.0.0.1", 19104)
    core.add_outbound_peer(peer)
    entered = threading.Event(); release = threading.Event()
    original_sync = p2p.sync_to_peer

    def blocked_sync(*_args, **_kwargs):
        entered.set()
        release.wait(1.0)
        return 0

    p2p.sync_to_peer = blocked_sync
    try:
        result = []
        worker = threading.Thread(
            target=lambda: result.append(core.sync_outbound_peer(peer)), daemon=True
        )
        worker.start()
        assert entered.wait(1.0), "sync did not start"
        core.remove_outbound_peer(peer)
        release.set(); worker.join(2.0)
        assert result and result[0]["ok"] is True
        assert peer not in core.peer_last_error
        assert peer not in core.peer_sync_successes
        assert peer not in core.peer_health_current_state
    finally:
        p2p.sync_to_peer = original_sync
    checks += 1
    print("[GREEN] late sync cannot recreate removed peer state")

    # Callers receive a defensive address snapshot, not the mutable backing list.
    core = AxvenCore(); peer = ("127.0.0.1", 19105); core.add_outbound_peer(peer)
    snapshot = core.outbound_peer_addresses(); snapshot.clear()
    assert core.outbound_peer_addresses() == [peer]
    checks += 1
    print("[GREEN] outbound peer address snapshots are defensive")

    print(f"SEC-101 peer lifecycle atomicity: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
'''
with SPEC.open("w", encoding="utf-8", newline="\n") as f:
    f.write(spec)

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (CORE, DAEMON, SPEC):
    data = path.read_bytes()
    manifest["files"][path.name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
with MANIFEST.open("w", encoding="utf-8", newline="\n") as f:
    f.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")

for temp in (Path("sec101_apply.py"), Path(".github/workflows/sec101_build.yml")):
    if temp.exists():
        temp.unlink()
