from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core.py"
DATADIR = ROOT / "datadir.py"
SPEC = ROOT / "security_sec126_peer_config_resource_bounds_spec.py"
MANIFEST = ROOT / "release_manifest.json"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"SEC-126 patch anchor {label!r}: expected 1, found {count}")
    return text.replace(old, new, 1)


core = CORE.read_text(encoding="utf-8").replace("\r\n", "\n")
core = replace_once(
    core,
    "class AxvenCore:\n    PEER_HEALTH_INCIDENT_HISTORY_LIMIT = 64\n    PEER_HEALTH_HISTORY_LIMIT = 64\n",
    "class AxvenCore:\n"
    "    # Configured outbound peers drive retry/health metadata and persisted\n"
    "    # configuration. Bound operator-controlled cardinality so local RPC or\n"
    "    # a corrupt config cannot grow those structures without limit.\n"
    "    MAX_CONFIGURED_PEERS = 256\n"
    "    PEER_HEALTH_INCIDENT_HISTORY_LIMIT = 64\n"
    "    PEER_HEALTH_HISTORY_LIMIT = 64\n",
    "configured peer constant",
)
core = replace_once(
    core,
    "    def add_outbound_peer(self, peer):\n"
    "        addr=self._parse_peer(peer)\n"
    "        if addr not in self.outbound_peers:\n"
    "            self.outbound_peers.append(addr)\n",
    "    def add_outbound_peer(self, peer):\n"
    "        addr=self._parse_peer(peer)\n"
    "        if addr not in self.outbound_peers:\n"
    "            if len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS:\n"
    "                raise ValueError(\"configured peer limit exceeded\")\n"
    "            self.outbound_peers.append(addr)\n",
    "runtime add guard",
)
CORE.write_text(core, encoding="utf-8", newline="\n")


datadir = DATADIR.read_text(encoding="utf-8").replace("\r\n", "\n")
datadir = replace_once(
    datadir,
    "from core import AxvenCore\n\nclass DataDir:\n",
    "from core import AxvenCore\n\n"
    "# Persisted peer configuration is small operator metadata, not chain state.\n"
    "# Keep enough room for MAX_CONFIGURED_PEERS entries even when 255-character\n"
    "# Unicode hosts expand under json.dumps(ensure_ascii=True).\n"
    "MAX_PEER_CONFIG_BYTES = 1024 * 1024\n\n"
    "class DataDir:\n",
    "peer config byte constant",
)
old_load = '''    def load_peers(self):
        if not self.peer_file.exists():
            return []
        import json
        raw=json.loads(self.peer_file.read_text(encoding="utf-8"))
        if not isinstance(raw,list):
            raise ValueError("peer config must be a list")
        peers=[]
        for peer in raw:
            if isinstance(peer,dict):
                if "host" not in peer or "port" not in peer:
                    raise ValueError("peer entry requires host and port")
                peer=(peer["host"],peer["port"])
            peers.append(AxvenCore._parse_peer(peer))
        return peers
'''
new_load = '''    def load_peers(self):
        if not self.peer_file.exists():
            return []
        import json
        with open(self.peer_file,"rb") as f:
            encoded=f.read(MAX_PEER_CONFIG_BYTES + 1)
        if len(encoded) > MAX_PEER_CONFIG_BYTES:
            raise ValueError("peer config too large")
        try:
            raw=json.loads(encoded.decode("utf-8"))
        except (UnicodeError,json.JSONDecodeError) as exc:
            raise ValueError("invalid peer config") from exc
        if not isinstance(raw,list):
            raise ValueError("peer config must be a list")
        if len(raw) > AxvenCore.MAX_CONFIGURED_PEERS:
            raise ValueError("too many configured peers")
        peers=[]
        for peer in raw:
            if isinstance(peer,dict):
                if "host" not in peer or "port" not in peer:
                    raise ValueError("peer entry requires host and port")
                peer=(peer["host"],peer["port"])
            peers.append(AxvenCore._parse_peer(peer))
        return peers
'''
datadir = replace_once(datadir, old_load, new_load, "bounded peer load")
old_save_prefix = '''    def save_peers(self,peers):
        import json
        normalized=[]
        for peer in peers:
            host,port=AxvenCore._parse_peer(peer)
            normalized.append({"host":host,"port":port})
        fd=None
'''
new_save_prefix = '''    def save_peers(self,peers):
        import json
        normalized=[]
        for peer in peers:
            if len(normalized) >= AxvenCore.MAX_CONFIGURED_PEERS:
                raise ValueError("too many configured peers")
            host,port=AxvenCore._parse_peer(peer)
            normalized.append({"host":host,"port":port})
        payload=(json.dumps(normalized,indent=2,sort_keys=True)+"\\n").encode("utf-8")
        if len(payload) > MAX_PEER_CONFIG_BYTES:
            raise ValueError("peer config too large")
        fd=None
'''
datadir = replace_once(datadir, old_save_prefix, new_save_prefix, "bounded peer save")
datadir = replace_once(
    datadir,
    '                f.write(json.dumps(normalized,indent=2,sort_keys=True)+"\\n")\n',
    '                f.write(payload.decode("utf-8"))\n',
    "pre-serialized peer payload",
)
DATADIR.write_text(datadir, encoding="utf-8", newline="\n")

spec = r'''#!/usr/bin/env python3
"""SEC-126 bound persisted and runtime configured-peer resource use."""

from __future__ import annotations

import inspect
import json
import tempfile
from pathlib import Path

import axven
import datadir
from core import AxvenCore
from datadir import DataDir


def expect_value_error(fn, text=None):
    try:
        fn()
    except ValueError as exc:
        return text is None or text in str(exc)
    return False


def main():
    checks=[]
    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "configured peer count and file-byte budgets pinned",
        AxvenCore.MAX_CONFIGURED_PEERS == 256
        and datadir.MAX_PEER_CONFIG_BYTES == 1024 * 1024,
    )

    with tempfile.TemporaryDirectory() as td:
        dd=DataDir(td)
        green("missing peer config remains an empty set", dd.load_peers() == [])

        canonical=[("seed.axven.org",18444),("127.0.0.1",19000)]
        dd.save_peers(canonical)
        green("canonical peer persistence round-trip preserved", dd.load_peers() == canonical)

        # The file-byte boundary must be enforced before UTF-8 or JSON parsing.
        dd.peer_file.write_bytes(b" " * (datadir.MAX_PEER_CONFIG_BYTES + 1))
        green(
            "oversized peer config rejected by bounded binary read",
            expect_value_error(dd.load_peers,"peer config too large"),
        )

        # Cardinality must be checked before per-peer parsing work begins.
        too_many=[{"host":"127.0.0.1","port":10000}] * (AxvenCore.MAX_CONFIGURED_PEERS + 1)
        dd.peer_file.write_text(json.dumps(too_many),encoding="utf-8")
        original_parse=AxvenCore._parse_peer
        parse_calls=[]
        def trap(peer):
            parse_calls.append(peer)
            raise AssertionError("peer parser must not run past list cardinality guard")
        AxvenCore._parse_peer=staticmethod(trap)
        try:
            list_guard=expect_value_error(dd.load_peers,"too many configured peers")
        finally:
            AxvenCore._parse_peer=staticmethod(original_parse)
        green(
            "oversized peer list rejected before per-peer parsing",
            list_guard and not parse_calls,
        )

        max_peers=[(f"peer-{i}.example",10000+i) for i in range(AxvenCore.MAX_CONFIGURED_PEERS)]
        dd.save_peers(max_peers)
        green(
            "exact configured-peer boundary persists and reloads",
            dd.load_peers() == max_peers,
        )

        # save_peers must reject before touching an existing good file.
        old_bytes=dd.peer_file.read_bytes()
        over=max_peers + [("overflow.example",20000)]
        green(
            "save rejects peer-count overflow without replacing prior config",
            expect_value_error(lambda: dd.save_peers(over),"too many configured peers")
            and dd.peer_file.read_bytes() == old_bytes,
        )

        yielded=[]
        def endlessish():
            for i in range(10000):
                yielded.append(i)
                yield (f"g-{i}.example",10000 + (i % 50000))
        green(
            "generator-backed peer save is consumption-bounded",
            expect_value_error(lambda: dd.save_peers(endlessish()),"too many configured peers")
            and len(yielded) == AxvenCore.MAX_CONFIGURED_PEERS + 1,
        )

        # json.dumps defaults to ensure_ascii=True.  Exercise the worst relevant
        # expansion shape to prove our own maximum valid save remains reloadable.
        unicode_host="😀" * 255
        unicode_peers=[(unicode_host,20000+i) for i in range(AxvenCore.MAX_CONFIGURED_PEERS)]
        dd.save_peers(unicode_peers)
        unicode_size=dd.peer_file.stat().st_size
        green(
            "maximum Unicode-heavy valid peer set fits its file budget",
            unicode_size <= datadir.MAX_PEER_CONFIG_BYTES
            and dd.load_peers() == unicode_peers,
        )

        # A config emitted at the exact boundary must remain restart-loadable.
        dd.save_peers(max_peers)
        loaded_core=dd.load_core()
        green(
            "load_core accepts a persisted peer set at the exact boundary",
            loaded_core.outbound_peers == max_peers,
        )

    core=AxvenCore()
    for i in range(AxvenCore.MAX_CONFIGURED_PEERS):
        core.add_outbound_peer((f"runtime-{i}.example",10000+i))
    before=list(core.outbound_peers)
    callback_calls=[]
    core.peer_persist_callback=lambda peers: callback_calls.append(list(peers))
    green(
        "runtime configured-peer boundary rejects a new overflow peer atomically",
        expect_value_error(
            lambda: core.add_outbound_peer(("runtime-overflow.example",30000)),
            "configured peer limit exceeded",
        )
        and core.outbound_peers == before
        and not callback_calls,
    )
    duplicate=before[-1]
    green(
        "duplicate peer remains idempotent at the configured-peer boundary",
        core.add_outbound_peer(duplicate) == duplicate
        and core.outbound_peers == before
        and not callback_calls,
    )

    load_src=inspect.getsource(DataDir.load_peers)
    save_src=inspect.getsource(DataDir.save_peers)
    add_src=inspect.getsource(AxvenCore.add_outbound_peer)
    green(
        "production persistence path bounds read count save count and payload bytes",
        "f.read(MAX_PEER_CONFIG_BYTES + 1)" in load_src
        and "len(raw) > AxvenCore.MAX_CONFIGURED_PEERS" in load_src
        and "len(normalized) >= AxvenCore.MAX_CONFIGURED_PEERS" in save_src
        and "len(payload) > MAX_PEER_CONFIG_BYTES" in save_src,
    )
    green(
        "production runtime add path enforces configured-peer cardinality before mutation",
        "len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS" in add_src
        and add_src.index("len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS")
            < add_src.index("self.outbound_peers.append(addr)"),
    )

    green(
        "peer resource hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-126 peer config resource bounds: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
SPEC.write_text(spec.replace("\r\n", "\n"), encoding="utf-8", newline="\n")

manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (CORE,DATADIR,SPEC):
    raw=path.read_bytes().replace(b"\r\n",b"\n")
    path.write_bytes(raw)
    manifest["files"][path.name]={
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest,indent=2,sort_keys=True)+"\n",
    encoding="utf-8",
    newline="\n",
)
print("SEC-126 patch applied")
