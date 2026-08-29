#!/usr/bin/env python3
"""SEC-146: exact public core numeric domains before sensitive work."""
from pathlib import Path
import inspect

import axven
import core as core_module
from core import AxvenCore

checks=[]

def green(condition, label):
    if not condition:
        raise AssertionError(label)
    checks.append(label)
    print(f"[GREEN] {label}")

def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        green(True,label)
    else:
        raise AssertionError(label)

class CoercionProbe:
    def __init__(self):
        self.int_called=False
        self.index_called=False
    def __int__(self):
        self.int_called=True
        raise AssertionError("__int__ must not run")
    def __index__(self):
        self.index_called=True
        raise AssertionError("__index__ must not run")

class TrapLock:
    def __enter__(self):
        raise AssertionError("sensitive lock acquired before numeric validation")
    def __exit__(self, exc_type, exc, tb):
        return False

# Shared validator is exact built-in int only and enforces caller-selected bounds.
green(AxvenCore._validate_service_int(7,"test",1,10) == 7,
      "canonical built-in service integer preserved")
for value in (True,False,1.0,"1",b"1",None):
    expect_value_error(
        lambda value=value: AxvenCore._validate_service_int(value,"test"),
        f"service integer coercion alias rejected: {type(value).__name__}",
    )
expect_value_error(lambda: AxvenCore._validate_service_int(0,"test",1,10),
                   "service integer lower bound enforced")
expect_value_error(lambda: AxvenCore._validate_service_int(11,"test",1,10),
                   "service integer upper bound enforced")
probe=CoercionProbe()
expect_value_error(lambda: AxvenCore._validate_service_int(probe,"test"),
                   "custom service integer object rejected")
green(not probe.int_called and not probe.index_called,
      "custom service integer coercion hooks never execute")

# Query limits must be rejected before their state locks are acquired.
core=AxvenCore()
original_chain_lock=core.chain._state_lock
core.chain._state_lock=TrapLock()
probe=CoercionProbe()
try:
    expect_value_error(lambda: core.recent_blocks(probe),
                       "recent-block coercion rejected before chain-state lock")
finally:
    core.chain._state_lock=original_chain_lock
green(not probe.int_called and not probe.index_called,
      "recent-block limit never invokes custom integer coercion")

original_mempool_lock=core.mempool._lock
core.mempool._lock=TrapLock()
probe=CoercionProbe()
try:
    expect_value_error(lambda: core.mempool_view(probe),
                       "mempool limit coercion rejected before mempool lock")
finally:
    core.mempool._lock=original_mempool_lock
green(not probe.int_called and not probe.index_called,
      "mempool limit never invokes custom integer coercion")

green(len(core.recent_blocks(0)) == 1,
      "legacy recent-block integer clamp remains compatible")
green(core.mempool_view(0)["size"] == 0,
      "legacy mempool integer clamp remains compatible")

# Mining count is exact and bounded before wallet/mining work.
mine_core=AxvenCore()
def wallet_trap():
    raise AssertionError("wallet work reached")
mine_core.require_wallet=wallet_trap
for value in (True,1.0,"1"):
    expect_value_error(lambda value=value: mine_core.mine(value),
                       f"mine count coercion rejected: {type(value).__name__}")
expect_value_error(lambda: mine_core.mine(0),"non-positive direct mine count rejected")
expect_value_error(lambda: mine_core.mine(1001),"oversized direct mine count rejected")
try:
    mine_core.mine(1)
except AssertionError as exc:
    green(str(exc) == "wallet work reached",
          "canonical direct mine count reaches normal wallet path")
else:
    raise AssertionError("canonical direct mine count did not reach wallet path")

# Send values are exact and RPC-equivalent bounded before wallet construction.
send_core=AxvenCore()
send_core.require_wallet=wallet_trap
scheme=axven.SCHEME_ED25519
recipient="N" + ("0" * 40)
for value in (True,1.0,"1"):
    expect_value_error(lambda value=value: send_core.send(scheme,recipient,value,0),
                       f"send amount coercion rejected: {type(value).__name__}")
for value in (True,1.0,"0"):
    expect_value_error(lambda value=value: send_core.send(scheme,recipient,1,value),
                       f"send fee coercion rejected: {type(value).__name__}")
expect_value_error(lambda: send_core.send(scheme,recipient,0,0),
                   "non-positive direct send amount rejected")
expect_value_error(lambda: send_core.send(scheme,recipient,1 << 63,0),
                   "oversized direct send amount rejected")
expect_value_error(lambda: send_core.send(scheme,recipient,1,-1),
                   "negative direct send fee rejected")
expect_value_error(lambda: send_core.send(scheme,recipient,1,1 << 63),
                   "oversized direct send fee rejected")
probe=CoercionProbe()
expect_value_error(lambda: send_core.send(scheme,recipient,probe,0),
                   "custom send amount rejected before wallet work")
green(not probe.int_called and not probe.index_called,
      "send value never invokes custom integer coercion")
try:
    send_core.send(scheme,recipient,1,0)
except AssertionError as exc:
    green(str(exc) == "wallet work reached",
          "canonical direct send values reach normal wallet path")
else:
    raise AssertionError("canonical direct send values did not reach wallet path")

# Direct peer sync must bound batch before outbound network I/O.
sync_core=AxvenCore()
original_sync=core_module.p2p.sync_to_peer
sync_calls=[]
def fake_sync(addr, session, limit=128, **kwargs):
    sync_calls.append((addr,limit))
    return 7
core_module.p2p.sync_to_peer=fake_sync
try:
    for value in (True,128.0,"128"):
        before=len(sync_calls)
        expect_value_error(lambda value=value: sync_core.sync_peer("127.0.0.1",1,value),
                           f"sync batch coercion rejected: {type(value).__name__}")
        green(len(sync_calls) == before,
              f"invalid {type(value).__name__} sync batch performs no network I/O")
    expect_value_error(lambda: sync_core.sync_peer("127.0.0.1",1,0),
                       "non-positive direct sync batch rejected")
    expect_value_error(lambda: sync_core.sync_peer("127.0.0.1",1,129),
                       "oversized direct sync batch rejected")
    probe=CoercionProbe()
    expect_value_error(lambda: sync_core.sync_peer("127.0.0.1",1,probe),
                       "custom sync batch rejected before network I/O")
    green(not probe.int_called and not probe.index_called,
          "sync batch never invokes custom integer coercion")
    green(sync_core.sync_peer("127.0.0.1",1,128) == 7
          and sync_calls[-1] == (("127.0.0.1",1),128),
          "maximum canonical direct sync batch reaches network path exactly")
finally:
    core_module.p2p.sync_to_peer=original_sync

# Production source must keep validation ahead of sensitive work and remove aliases.
recent_src=inspect.getsource(AxvenCore.recent_blocks)
mempool_src=inspect.getsource(AxvenCore.mempool_view)
mine_src=inspect.getsource(AxvenCore.mine)
send_src=inspect.getsource(AxvenCore.send)
sync_src=inspect.getsource(AxvenCore.sync_peer)
green(recent_src.index("_validate_service_int") < recent_src.index("with self.chain._state_lock"),
      "recent-block numeric validation precedes chain lock in production")
green(mempool_src.index("_validate_service_int") < mempool_src.index("with _mempool_guard"),
      "mempool numeric validation precedes mempool lock in production")
green(mine_src.index("_validate_service_int") < mine_src.index("require_wallet"),
      "mine count validation precedes wallet work in production")
green(send_src.index("_validate_service_int") < send_src.index("require_wallet"),
      "send numeric validation precedes wallet work in production")
green(sync_src.index("_validate_service_int") < sync_src.index("_parse_peer"),
      "sync batch validation precedes peer/network work in production")
source=Path("core.py").read_text(encoding="utf-8")
green("int(limit)" not in recent_src and "int(limit)" not in mempool_src,
      "query-limit attacker integer coercion removed")
green("int(amount), int(fee)" not in send_src and "limit=int(batch)" not in sync_src,
      "send and sync attacker integer coercion removed")

green(axven.CHAIN_ID == "axven-devnet-2"
      and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
      and axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
      "core numeric-domain hardening leaves canonical chain identity unchanged")

print(f"SEC-146 core numeric domain: {len(checks)}/{len(checks)} GREEN")
