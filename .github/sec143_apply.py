from pathlib import Path
import hashlib
import json

CORE=Path("core.py")
RPC=Path("rpc.py")

core=CORE.read_text(encoding="utf-8")
old='''    def start_p2p(self, host="127.0.0.1", port=0):
        if self.p2p_server is not None:
            return self.p2p_server.address
        if len(str(host)) > 255:
            raise ValueError("P2P listener host too long")
        self.p2p_server = p2p.NodeServer(
            self.chain, self.mempool, host=host, port=int(port)
        ).start()
        return self.p2p_server.address

    @staticmethod
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
        if not host:
            raise ValueError("peer host required")
        if len(host) > 255:
            raise ValueError("peer host too long")
        if not 1 <= port <= 65535:
            raise ValueError("invalid peer port")
        return (host,port)
'''
new='''    @staticmethod
    def _validate_p2p_listener_endpoint(host, port):
        if type(host) is not str:
            raise ValueError("P2P listener host must be string")
        if len(host) > 255:
            raise ValueError("P2P listener host too long")
        if type(port) is not int or port < 0 or port > 65535:
            raise ValueError("invalid P2P listener port")
        return host,port

    def start_p2p(self, host="127.0.0.1", port=0):
        host,port=self._validate_p2p_listener_endpoint(host,port)
        if self.p2p_server is not None:
            return self.p2p_server.address
        self.p2p_server = p2p.NodeServer(
            self.chain, self.mempool, host=host, port=port
        ).start()
        return self.p2p_server.address

    @staticmethod
    def _parse_peer(peer):
        if isinstance(peer,(tuple,list)) and len(peer)==2:
            if type(peer[0]) is not str:
                raise ValueError("peer host must be string")
            if type(peer[1]) is not int:
                raise ValueError("invalid peer port")
            host=peer[0].strip()
            port=peer[1]
        else:
            if type(peer) is not str:
                raise ValueError("peer must be host:port")
            raw=peer.strip()
            if ":" not in raw:
                raise ValueError("peer must be host:port")
            host,port_text=raw.rsplit(":",1)
            host=host.strip()
            port_text=port_text.strip()
            if (
                not port_text
                or len(port_text) > 5
                or not port_text.isascii()
                or not port_text.isdecimal()
            ):
                raise ValueError("invalid peer port")
            port=int(port_text)
        if not host:
            raise ValueError("peer host required")
        if len(host) > 255:
            raise ValueError("peer host too long")
        if not 1 <= port <= 65535:
            raise ValueError("invalid peer port")
        return (host,port)
'''
if old not in core:
    raise SystemExit("SEC-143 core endpoint anchor not found")
CORE.write_text(core.replace(old,new,1),encoding="utf-8",newline="\n")

rpc=RPC.read_text(encoding="utf-8")
old='''def _require_rpc_int(value, label):
    if type(value) is not int:
        raise RPCError(f"{label} must be integer")
    return value
'''
new='''def _require_rpc_int(value, label):
    if type(value) is not int:
        raise RPCError(f"{label} must be integer")
    return value


def _require_rpc_host(value, label):
    if type(value) is not str:
        raise RPCError(f"{label} must be string")
    if len(value) > 255:
        raise RPCError(f"{label} too long")
    return value
'''
if old not in rpc:
    raise SystemExit("SEC-143 rpc helper anchor not found")
rpc=rpc.replace(old,new,1)
replacements={
'''        if method == "add_peer":
            port = _require_rpc_int(p["port"], "peer port")
''':'''        if method == "add_peer":
            host = _require_rpc_host(p["host"], "peer host")
            port = _require_rpc_int(p["port"], "peer port")
''',
'''            host, port = self.core.add_outbound_peer((p["host"], port))
''':'''            host, port = self.core.add_outbound_peer((host, port))
''',
'''        if method == "remove_peer":
            port = _require_rpc_int(p["port"], "peer port")
''':'''        if method == "remove_peer":
            host = _require_rpc_host(p["host"], "peer host")
            port = _require_rpc_int(p["port"], "peer port")
''',
'''            return self.core.remove_outbound_peer((p["host"], port))
''':'''            return self.core.remove_outbound_peer((host, port))
''',
'''        if method == "start_p2p":
            port = _require_rpc_int(p.get("port", 0), "start_p2p port")
''':'''        if method == "start_p2p":
            host = _require_rpc_host(p.get("host", "127.0.0.1"), "start_p2p host")
            port = _require_rpc_int(p.get("port", 0), "start_p2p port")
''',
'''                p.get("host", "127.0.0.1"),
                port,
''':'''                host,
                port,
''',
'''        if method == "sync_peer":
            batch = _require_rpc_int(p.get("batch", 128), "sync batch")
''':'''        if method == "sync_peer":
            host = _require_rpc_host(p["host"], "sync peer host")
            batch = _require_rpc_int(p.get("batch", 128), "sync batch")
''',
'''                    p["host"],
                    port,
''':'''                    host,
                    port,
''',
}
for anchor,replacement in replacements.items():
    if anchor not in rpc:
        raise SystemExit(f"SEC-143 rpc route anchor not found: {anchor[:40]!r}")
    rpc=rpc.replace(anchor,replacement,1)
RPC.write_text(rpc,encoding="utf-8",newline="\n")

spec=r'''#!/usr/bin/env python3
"""SEC-143 enforces exact peer endpoint types before persistence, DNS, or sockets."""
import inspect
import json
import tempfile
from pathlib import Path

import axven
import core as core_module
import datadir
import p2p
import rpc


def expect_value_error(call,label):
    try:
        call()
    except ValueError:
        pass
    else:
        raise AssertionError(label)
    print("[GREEN]",label)


def main():
    checks=0
    parse=core_module.AxvenCore._parse_peer
    assert parse((" node.axven.org ",31337)) == ("node.axven.org",31337)
    assert parse(["127.0.0.1",65535]) == ("127.0.0.1",65535)
    assert parse(" node.axven.org : 31337 ") == ("node.axven.org",31337)
    print("[GREEN] canonical tuple list and host:port forms preserve normalization"); checks+=1

    for value in ({},[],True,False,1,1.0,b"host",None):
        expect_value_error(lambda value=value: parse((value,31337)),f"peer host coercion alias rejected: {type(value).__name__}")
        checks+=1
    for value in ("31337",31337.0,True,False,b"31337",None):
        expect_value_error(lambda value=value: parse(("node.axven.org",value)),f"peer port coercion alias rejected: {type(value).__name__}")
        checks+=1
    for value in ({},True,1,1.0,b"node:31337",None,["node"]):
        expect_value_error(lambda value=value: parse(value),f"whole peer coercion alias rejected: {type(value).__name__}")
        checks+=1
    for raw in ("node:+1","node:-1","node:1.0","node:000001","node:１２３","node:abc","node:"):
        expect_value_error(lambda raw=raw: parse(raw),f"noncanonical raw peer port rejected: {raw!r}")
        checks+=1
    assert parse("node:1") == ("node",1) and parse("node:65535") == ("node",65535)
    print("[GREEN] canonical raw peer port boundaries remain accepted"); checks+=1

    core=core_module.AxvenCore()
    persisted=[]
    core.peer_persist_callback=lambda peers: persisted.append(peers)
    expect_value_error(lambda: core.add_outbound_peer(({},31337)),"invalid endpoint rejected before peer persistence")
    assert persisted == [] and core.outbound_peer_addresses() == []
    checks+=1

    original_sync=p2p.sync_to_peer
    network_calls=[]
    p2p.sync_to_peer=lambda *args,**kwargs: network_calls.append((args,kwargs)) or 0
    try:
        expect_value_error(lambda: core.sync_peer({},31337,1),"invalid sync host rejected before network work"); checks+=1
        expect_value_error(lambda: core.sync_peer("node","31337",1),"invalid sync port rejected before network work"); checks+=1
        assert network_calls == []
    finally:
        p2p.sync_to_peer=original_sync

    original_server=p2p.NodeServer
    server_calls=[]
    def fake_server(*args,**kwargs):
        server_calls.append((args,kwargs))
        raise AssertionError("socket construction reached")
    p2p.NodeServer=fake_server
    try:
        for host,port in (({},0),(True,0),("127.0.0.1","0"),("127.0.0.1",0.0),("127.0.0.1",True)):
            expect_value_error(lambda host=host,port=port: core.start_p2p(host,port),f"listener endpoint type rejected before bind: {type(host).__name__}/{type(port).__name__}")
            checks+=1
        assert server_calls == []
    finally:
        p2p.NodeServer=original_server

    with tempfile.TemporaryDirectory() as td:
        data=datadir.DataDir(td)
        canonical=[(" node.axven.org ",31337),("127.0.0.1",1)]
        data.save_peers(canonical)
        assert data.load_peers() == [("node.axven.org",31337),("127.0.0.1",1)]
        print("[GREEN] canonical persisted peer round-trip preserved"); checks+=1
        malformed=(
            [{"host":{},"port":31337}],
            [{"host":[],"port":31337}],
            [{"host":True,"port":31337}],
            [{"host":"node","port":"31337"}],
            [{"host":"node","port":31337.0}],
            [{"host":"node","port":True}],
        )
        for payload in malformed:
            data.peer_file.write_text(json.dumps(payload),encoding="utf-8")
            expect_value_error(data.load_peers,f"persisted peer type alias rejected: {payload[0]!r}")
            checks+=1

    class FakeCore:
        def __init__(self): self.calls=[]
        def add_outbound_peer(self,peer): self.calls.append(("add",peer)); return peer
        def remove_outbound_peer(self,peer): self.calls.append(("remove",peer)); return {"removed":True}
        def start_p2p(self,host,port): self.calls.append(("start",host,port)); return (host,port)
        def sync_peer(self,host,port,batch): self.calls.append(("sync",host,port,batch)); return 0
    fake=FakeCore(); dispatch=rpc.RPCDispatcher(fake)
    routes=(
        ("add_peer",lambda host:{"host":host,"port":31337}),
        ("remove_peer",lambda host:{"host":host,"port":31337}),
        ("start_p2p",lambda host:{"host":host,"port":0}),
        ("sync_peer",lambda host:{"host":host,"port":31337,"batch":1}),
    )
    for method,params in routes:
        for host in ({},[],True,1,1.0,None):
            before=len(fake.calls)
            try:
                dispatch.call(method,params(host))
            except rpc.RPCError:
                pass
            else:
                raise AssertionError(f"{method} accepted non-string host")
            assert len(fake.calls) == before
        print("[GREEN]",method,"rejects non-string host before core dispatch"); checks+=1
    assert dispatch.call("add_peer",{"host":" node.axven.org ","port":31337}) == {"host":" node.axven.org ","port":31337}
    assert dispatch.call("start_p2p",{"host":"127.0.0.1","port":0}) == {"host":"127.0.0.1","port":0}
    print("[GREEN] canonical RPC endpoint dispatch remains compatible"); checks+=1

    parse_src=inspect.getsource(core_module.AxvenCore._parse_peer)
    assert "str(peer[0])" not in parse_src and "int(peer[1])" not in parse_src and "raw=str(peer)" not in parse_src
    assert "type(peer[0]) is not str" in parse_src and "type(peer[1]) is not int" in parse_src
    start_src=inspect.getsource(core_module.AxvenCore.start_p2p)
    assert "len(str(host))" not in start_src and "port=int(port)" not in start_src
    assert "_validate_p2p_listener_endpoint(host,port)" in start_src
    rpc_src=inspect.getsource(rpc.RPCDispatcher.call)
    assert rpc_src.count("_require_rpc_host(") == 4
    print("[GREEN] production endpoint paths contain no attacker-controlled host or tuple-port coercion"); checks+=1

    assert (
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    )
    print("[GREEN] peer endpoint hardening leaves canonical chain identity unchanged"); checks+=1
    print(f"SEC-143 peer endpoint type domain: {checks}/{checks} GREEN")

if __name__ == "__main__":
    main()
'''
SPEC=Path("security_sec143_peer_endpoint_type_domain_spec.py")
SPEC.write_text(spec,encoding="utf-8",newline="\n")

manifest_path=Path("release_manifest.json")
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
for path in (CORE,RPC,SPEC):
    raw=path.read_bytes()
    manifest["files"][path.as_posix()]={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
manifest_path.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8",newline="\n")
