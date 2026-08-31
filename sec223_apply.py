#!/usr/bin/env python3
"""Temporary branch-only SEC-223 patch helper; removed before PR."""
from pathlib import Path
import hashlib
import json

path = Path("core.py")
text = path.read_text(encoding="utf-8")

old_import = "from contextlib import nullcontext\nfrom typing import Optional, Tuple\n"
new_import = "from contextlib import nullcontext\nfrom concurrent.futures import ThreadPoolExecutor\nfrom typing import Optional, Tuple\n"
if old_import in text:
    text = text.replace(old_import, new_import, 1)
elif new_import not in text:
    raise SystemExit("SEC-223 import anchor missing")

old_constant = "    MAX_CONFIGURED_PEERS = 256\n"
new_constant = (
    "    MAX_CONFIGURED_PEERS = 256\n"
    "    # SEC-223: preserve full configured-peer propagation while bounding\n"
    "    # simultaneous outbound sockets/threads and eliminating serial latency\n"
    "    # amplification across the configured peer set.\n"
    "    MAX_PROPAGATION_WORKERS = 16\n"
)
if old_constant in text and "MAX_PROPAGATION_WORKERS" not in text:
    text = text.replace(old_constant, new_constant, 1)
elif "MAX_PROPAGATION_WORKERS = 16" not in text:
    raise SystemExit("SEC-223 constant anchor missing")

old_methods = '''    def _propagate_block_outbound(self, block):
        for addr in self.outbound_peer_addresses():
            try:
                def remote_host_gate(remote_host):
                    source_host=self._canonical_resolved_peer_host(remote_host)
                    return self._admit_resolved_peer_host(addr,source_host)
                p2p.propagate_block(addr,block,remote_host_gate=remote_host_gate)
                error=None
            except Exception as e:
                error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error

    def _propagate_tx_outbound(self, tx):
        for addr in self.outbound_peer_addresses():
            try:
                def remote_host_gate(remote_host):
                    source_host=self._canonical_resolved_peer_host(remote_host)
                    return self._admit_resolved_peer_host(addr,source_host)
                p2p.propagate_tx(addr,tx,remote_host_gate=remote_host_gate)
                error=None
            except Exception as e:
                error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error
'''
new_methods = '''    def _propagate_one_outbound(self, addr, payload, transport):
        try:
            def remote_host_gate(remote_host):
                source_host=self._canonical_resolved_peer_host(remote_host)
                return self._admit_resolved_peer_host(addr,source_host)
            transport(addr,payload,remote_host_gate=remote_host_gate)
            error=None
        except Exception as e:
            error=f"{type(e).__name__}: {e}"
        with _peer_guard(self):
            # SEC-101: a late worker must never recreate health state after an
            # operator removes the configured peer while propagation is active.
            if addr in self.outbound_peers:
                self.peer_last_error[addr]=error

    def _propagate_outbound(self, payload, transport):
        peers=self.outbound_peer_addresses()
        if not peers:
            return
        workers=min(self.MAX_PROPAGATION_WORKERS,len(peers))
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="axven-propagation",
        ) as executor:
            futures=[
                executor.submit(self._propagate_one_outbound,addr,payload,transport)
                for addr in peers
            ]
            # Every configured peer still receives one attempt. Waiting here
            # preserves existing send/mine completion semantics while the fixed
            # worker cap prevents serial per-peer timeout multiplication.
            for future in futures:
                future.result()

    def _propagate_block_outbound(self, block):
        self._propagate_outbound(block,p2p.propagate_block)

    def _propagate_tx_outbound(self, tx):
        self._propagate_outbound(tx,p2p.propagate_tx)
'''
if old_methods in text:
    text = text.replace(old_methods, new_methods, 1)
elif new_methods not in text:
    raise SystemExit("SEC-223 propagation method anchor missing")

path.write_text(text, encoding="utf-8")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
files = manifest["files"]
for name in ("core.py", "security_sec223_bounded_propagation_fanout_spec.py"):
    raw = Path(name).read_bytes()
    files[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
manifest["files"] = dict(sorted(files.items()))
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
