#!/usr/bin/env python3
"""Checkpoint 44 acceptance contract: peer health summary."""

from core import AxvenCore
from rpc import RPCDispatcher

checks=[]

def ok(name, condition):
    assert condition, name
    checks.append(name)

core=AxvenCore()

summary=core.peer_health_summary()

ok("empty total zero", summary["total"] == 0)
ok("empty healthy zero", summary["healthy"] == 0)
ok("empty unhealthy zero", summary["unhealthy"] == 0)
ok("empty successes zero", summary["total_sync_successes"] == 0)
ok("empty failures zero", summary["total_consecutive_failures"] == 0)

p1=("127.0.0.1",19001)
p2=("127.0.0.1",19002)

core.add_outbound_peer(p1)
core.add_outbound_peer(p2)

core.peer_sync_successes[p1]=3
core.peer_consecutive_failures[p1]=0
core.peer_last_error[p1]=None

core.peer_sync_successes[p2]=1
core.peer_consecutive_failures[p2]=2
core.peer_last_error[p2]="ConnectionRefusedError: offline"

summary=core.peer_health_summary()

ok("total peers counted", summary["total"] == 2)
ok("healthy peers counted", summary["healthy"] == 1)
ok("unhealthy peers counted", summary["unhealthy"] == 1)
ok("success totals aggregated", summary["total_sync_successes"] == 4)
ok("failure totals aggregated", summary["total_consecutive_failures"] == 2)

rpc=RPCDispatcher(core)
rpc_summary=rpc.call("get_peer_health")

ok("RPC health summary matches core", rpc_summary == summary)

core.remove_outbound_peer(p2)
summary=core.peer_health_summary()

ok("removed peer leaves one total", summary["total"] == 1)
ok("removed unhealthy peer clears unhealthy count", summary["unhealthy"] == 0)
ok("remaining peer healthy", summary["healthy"] == 1)

print(f"Checkpoint 44 peer health summary: {len(checks)}/{len(checks)} GREEN")
