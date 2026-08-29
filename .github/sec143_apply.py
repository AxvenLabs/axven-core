from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
core_path = ROOT / "core.py"
text = core_path.read_text(encoding="utf-8")

old_start = '''    def start_p2p(self, host="127.0.0.1", port=0):
        if self.p2p_server is not None:
            return self.p2p_server.address
        if len(str(host)) > 255:
            raise ValueError("P2P listener host too long")
        self.p2p_server = p2p.NodeServer(
'''
new_start = '''    def start_p2p(self, host="127.0.0.1", port=0):
        if self.p2p_server is not None:
            return self.p2p_server.address
        # Listener hosts are textual socket authorities. Reject coercion
        # aliases before socket/server construction instead of stringifying
        # attacker-controlled JSON values at the service boundary.
        if type(host) is not str:
            raise ValueError("P2P listener host must be string")
        if len(host) > 255:
            raise ValueError("P2P listener host too long")
        self.p2p_server = p2p.NodeServer(
'''
if text.count(old_start) != 1:
    raise SystemExit("SEC-143 start_p2p anchor mismatch")
text = text.replace(old_start, new_start, 1)

old_parse = '''    @staticmethod
    def _parse_peer(peer):
        if isinstance(peer,(tuple,list)) and len(peer)==2:
            host=str(peer[0]).strip()
            port=int(peer[1])
        else:
            raw=str(peer).strip()
            if ":" not in raw:
                raise ValueError("peer must be host:port")
            host,port=raw.rsplit(":",1)
            host=host.strip()
            port=int(port)
'''
new_parse = '''    @staticmethod
    def _parse_peer(peer):
        if isinstance(peer,(tuple,list)) and len(peer)==2:
            # Structured peer endpoints must carry an exact textual host.
            # Do not accept list/dict/bool/int/bytes aliases through str().
            if type(peer[0]) is not str:
                raise ValueError("peer host must be string")
            host=peer[0].strip()
            port=int(peer[1])
        else:
            # Scalar peer endpoints use the legacy explicit host:port form.
            # Reject arbitrary objects before any __str__ coercion can run.
            if type(peer) is not str:
                raise ValueError("peer must be host:port string")
            raw=peer.strip()
            if ":" not in raw:
                raise ValueError("peer must be host:port")
            host,port=raw.rsplit(":",1)
            host=host.strip()
            port=int(port)
'''
if text.count(old_parse) != 1:
    raise SystemExit("SEC-143 _parse_peer anchor mismatch")
text = text.replace(old_parse, new_parse, 1)
core_path.write_text(text, encoding="utf-8", newline="")

spec = r'''#!/usr/bin/env python3
"""SEC-143 exact peer/listener host type-domain regression contract."""

from core import AxvenCore
import p2p


def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def main():
    checks = 0

    assert AxvenCore._parse_peer(("127.0.0.1", 31337)) == ("127.0.0.1", 31337)
    checks += 1
    print("[GREEN] canonical tuple peer preserved")

    assert AxvenCore._parse_peer(["node.axven.org", 31337]) == ("node.axven.org", 31337)
    checks += 1
    print("[GREEN] canonical list peer preserved")

    assert AxvenCore._parse_peer("node.axven.org:31337") == ("node.axven.org", 31337)
    checks += 1
    print("[GREEN] canonical scalar peer preserved")

    assert AxvenCore._parse_peer(("  node.axven.org  ", 31337)) == ("node.axven.org", 31337)
    checks += 1
    print("[GREEN] peer host whitespace normalization preserved")

    maximum = "a" * 255
    assert AxvenCore._parse_peer((maximum, 31337)) == (maximum, 31337)
    checks += 1
    print("[GREEN] maximum peer host preserved")

    for bad in ([], {}, True, 7, b"node.axven.org", None):
        expect_value_error(
            lambda bad=bad: AxvenCore._parse_peer((bad, 31337)),
            f"structured peer host type {type(bad).__name__} rejected",
        )
        checks += 1

    class Sneaky:
        called = False
        def __str__(self):
            self.called = True
            return "node.axven.org:31337"

    sneaky = Sneaky()
    expect_value_error(lambda: AxvenCore._parse_peer(sneaky), "scalar peer object rejected")
    assert not sneaky.called
    checks += 1
    print("[GREEN] scalar peer rejected without __str__ coercion")

    original_sync = p2p.sync_to_peer
    sync_calls = []
    def fake_sync(*args, **kwargs):
        sync_calls.append((args, kwargs))
        return 0
    p2p.sync_to_peer = fake_sync
    try:
        core = object.__new__(AxvenCore)
        core.chain = object()
        core.mempool = object()
        before = len(sync_calls)
        expect_value_error(lambda: core.sync_peer({"host": "127.0.0.1"}, 31337, 1), "sync_peer dict host rejected pre-I/O")
        assert len(sync_calls) == before
        checks += 1

        before = len(sync_calls)
        expect_value_error(lambda: core.sync_peer(True, 31337, 1), "sync_peer bool host rejected pre-I/O")
        assert len(sync_calls) == before
        checks += 1
    finally:
        p2p.sync_to_peer = original_sync

    original_server = p2p.NodeServer
    server_calls = []
    class FakeNodeServer:
        def __init__(self, *args, **kwargs):
            server_calls.append((args, kwargs))
        def start(self):
            return self
        @property
        def address(self):
            return ("127.0.0.1", 0)
    p2p.NodeServer = FakeNodeServer
    try:
        core = object.__new__(AxvenCore)
        core.chain = object()
        core.mempool = object()
        core.p2p_server = None
        before = len(server_calls)
        expect_value_error(lambda: core.start_p2p(["127.0.0.1"], 0), "listener list host rejected pre-bind")
        assert len(server_calls) == before
        checks += 1

        before = len(server_calls)
        expect_value_error(lambda: core.start_p2p(False, 0), "listener bool host rejected pre-bind")
        assert len(server_calls) == before
        checks += 1
    finally:
        p2p.NodeServer = original_server

    assert checks == 16
    print("SEC-143 peer host type domain: 16/16 GREEN")


if __name__ == "__main__":
    main()
'''
spec_path = ROOT / "security_sec143_peer_host_type_domain_spec.py"
spec_path.write_text(spec, encoding="utf-8", newline="")

manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for rel in ("core.py", "security_sec143_peer_host_type_domain_spec.py"):
    data = (ROOT / rel).read_bytes()
    manifest["files"][rel] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="",
)
