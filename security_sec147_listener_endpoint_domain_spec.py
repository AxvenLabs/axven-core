#!/usr/bin/env python3
"""SEC-147: exact listener endpoint domains before service/socket resources."""
import inspect

import axven
import explorer
import p2p
import rpc

checks=[]

def green(condition,label):
    if not condition:
        raise AssertionError(label)
    checks.append(label)
    print(f"[GREEN] {label}")

def expect_value_error(fn,label):
    try:
        fn()
    except ValueError:
        green(True,label)
    else:
        raise AssertionError(label)

class HostProbe:
    def __init__(self):
        self.eq_called=False
        self.str_called=False
    def __eq__(self,other):
        self.eq_called=True
        raise AssertionError("host equality coercion must not run")
    def __str__(self):
        self.str_called=True
        raise AssertionError("host string coercion must not run")

class PortProbe:
    def __init__(self):
        self.int_called=False
        self.index_called=False
    def __int__(self):
        self.int_called=True
        raise AssertionError("port integer coercion must not run")
    def __index__(self):
        self.index_called=True
        raise AssertionError("port index coercion must not run")

class ChainProbe:
    def __init__(self):
        self.bool_called=False
    def __bool__(self):
        self.bool_called=True
        raise AssertionError("chain construction path must not run")

class FakeHTTPServer:
    calls=[]
    def __init__(self,address,handler):
        type(self).calls.append(address)
        self.server_address=address
    def shutdown(self): pass
    def server_close(self): pass

# Helper-level endpoint contracts.
for host in ("127.0.0.1","localhost","::1"):
    green(rpc._validate_rpc_listener_endpoint(host,0)==(host,0),
          f"RPC canonical loopback host preserved: {host}")
    green(explorer._validate_explorer_listener_endpoint(host,65535)==(host,65535),
          f"Explorer canonical loopback host preserved: {host}")
expect_value_error(lambda: rpc._validate_rpc_listener_endpoint("0.0.0.0",0),
                   "RPC public bind remains rejected")
expect_value_error(lambda: explorer._validate_explorer_listener_endpoint("0.0.0.0",0),
                   "Explorer public bind remains rejected")

for module,label,validator in (
    (rpc,"RPC",rpc._validate_rpc_listener_endpoint),
    (explorer,"Explorer",explorer._validate_explorer_listener_endpoint),
):
    for value in (True,1,b"127.0.0.1",None,["127.0.0.1"]):
        expect_value_error(lambda value=value,validator=validator: validator(value,0),
                           f"{label} listener host type rejected: {type(value).__name__}")
    hp=HostProbe()
    expect_value_error(lambda hp=hp,validator=validator: validator(hp,0),
                       f"{label} custom host rejected")
    green(not hp.eq_called and not hp.str_called,
          f"{label} custom host hooks never execute")
    for value in (True,1.0,"1",b"1",None):
        expect_value_error(lambda value=value,validator=validator: validator("127.0.0.1",value),
                           f"{label} listener port type rejected: {type(value).__name__}")
    for value in (-1,65536):
        expect_value_error(lambda value=value,validator=validator: validator("127.0.0.1",value),
                           f"{label} listener port bound rejected: {value}")
    pp=PortProbe()
    expect_value_error(lambda pp=pp,validator=validator: validator("127.0.0.1",pp),
                       f"{label} custom port rejected")
    green(not pp.int_called and not pp.index_called,
          f"{label} custom port hooks never execute")

# Constructors validate before dispatcher/HTTP resources; canonical endpoints pass unchanged.
old_rpc_http=rpc.BoundedThreadingHTTPServer
old_rpc_dispatcher=rpc.RPCDispatcher
rpc.BoundedThreadingHTTPServer=FakeHTTPServer
try:
    FakeHTTPServer.calls=[]
    server=rpc.RPCServer(object(),"127.0.0.1",65535)
    green(FakeHTTPServer.calls==[("127.0.0.1",65535)],
          "RPC canonical endpoint reaches HTTP server unchanged")
    before=len(FakeHTTPServer.calls)
    pp=PortProbe()
    expect_value_error(lambda: rpc.RPCServer(object(),"127.0.0.1",pp),
                       "RPC constructor rejects custom port before HTTP server")
    green(len(FakeHTTPServer.calls)==before and not pp.int_called and not pp.index_called,
          "RPC invalid port allocates no HTTP server and runs no coercion")
finally:
    rpc.BoundedThreadingHTTPServer=old_rpc_http

old_explorer_http=explorer.BoundedThreadingHTTPServer
explorer.BoundedThreadingHTTPServer=FakeHTTPServer
try:
    FakeHTTPServer.calls=[]
    server=explorer.ExplorerServer(object(),"localhost",0)
    green(FakeHTTPServer.calls==[("localhost",0)],
          "Explorer canonical endpoint reaches HTTP server unchanged")
    before=len(FakeHTTPServer.calls)
    hp=HostProbe()
    expect_value_error(lambda: explorer.ExplorerServer(object(),hp,0),
                       "Explorer constructor rejects custom host before HTTP server")
    green(len(FakeHTTPServer.calls)==before and not hp.eq_called and not hp.str_called,
          "Explorer invalid host allocates no HTTP server and runs no coercion")
finally:
    explorer.BoundedThreadingHTTPServer=old_explorer_http

# Direct P2P NodeServer now has the same exact listener domain as the core wrapper.
for host in ("127.0.0.1","0.0.0.0","node.axven.org","a"*255,""):
    green(p2p._validate_p2p_listener_endpoint(host,0)==(host,0),
          f"P2P listener host semantics preserved: len={len(host)}")
green(p2p._validate_p2p_listener_endpoint("127.0.0.1",65535)==("127.0.0.1",65535),
      "P2P maximum listener port preserved")
expect_value_error(lambda: p2p._validate_p2p_listener_endpoint("a"*256,0),
                   "P2P oversized listener host rejected")
for value in (True,1,b"host",None,["host"]):
    expect_value_error(lambda value=value: p2p._validate_p2p_listener_endpoint(value,0),
                       f"P2P listener host type rejected: {type(value).__name__}")
for value in (True,1.0,"1",b"1",None,-1,65536):
    expect_value_error(lambda value=value: p2p._validate_p2p_listener_endpoint("127.0.0.1",value),
                       f"P2P listener port rejected: {value!r}")
hp=HostProbe()
expect_value_error(lambda: p2p._validate_p2p_listener_endpoint(hp,0),
                   "P2P custom host rejected")
green(not hp.eq_called and not hp.str_called,
      "P2P custom host hooks never execute")
pp=PortProbe()
expect_value_error(lambda: p2p._validate_p2p_listener_endpoint("127.0.0.1",pp),
                   "P2P custom port rejected")
green(not pp.int_called and not pp.index_called,
      "P2P custom port hooks never execute")

chain_probe=ChainProbe()
pp=PortProbe()
expect_value_error(lambda: p2p.NodeServer(chain_probe,None,"127.0.0.1",pp),
                   "NodeServer rejects invalid endpoint before chain/session work")
green(not chain_probe.bool_called and not pp.int_called and not pp.index_called,
      "NodeServer invalid endpoint runs neither chain nor numeric coercion hooks")
node=p2p.NodeServer(axven.Blockchain(),None,"0.0.0.0",0)
green(node.address==("0.0.0.0",0),
      "direct NodeServer public listener semantics preserved before start")

# Production-order/static invariants.
rpc_src=inspect.getsource(rpc.RPCServer.__init__)
explorer_src=inspect.getsource(explorer.ExplorerServer.__init__)
p2p_src=inspect.getsource(p2p.NodeServer.__init__)
green(rpc_src.index("_validate_rpc_listener_endpoint") < rpc_src.index("RPCDispatcher"),
      "RPC endpoint validation precedes dispatcher creation")
green(explorer_src.index("_validate_explorer_listener_endpoint") < explorer_src.index("BoundedThreadingHTTPServer"),
      "Explorer endpoint validation precedes HTTP server creation")
green(p2p_src.index("_validate_p2p_listener_endpoint") < p2p_src.index("axven.Blockchain"),
      "P2P endpoint validation precedes chain/session creation")
green("int(port)" not in rpc_src and "int(port)" not in explorer_src,
      "HTTP listener attacker integer coercion removed")
green("type(host) is not str" in inspect.getsource(rpc._validate_rpc_listener_endpoint)
      and "type(host) is not str" in inspect.getsource(explorer._validate_explorer_listener_endpoint)
      and "type(host) is not str" in inspect.getsource(p2p._validate_p2p_listener_endpoint),
      "listener hosts use exact built-in string domains")
green("type(port) is not int" in inspect.getsource(rpc._validate_rpc_listener_endpoint)
      and "type(port) is not int" in inspect.getsource(explorer._validate_explorer_listener_endpoint)
      and "type(port) is not int" in inspect.getsource(p2p._validate_p2p_listener_endpoint),
      "listener ports use exact built-in integer domains")
green(axven.CHAIN_ID=="axven-devnet-2"
      and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
      and axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
      "listener endpoint hardening leaves canonical chain identity unchanged")

print(f"SEC-147 listener endpoint domain: {len(checks)}/{len(checks)} GREEN")
