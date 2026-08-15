#!/usr/bin/env python3
"""Checkpoint 49 acceptance contract: peer recovery summary."""

from core import AxvenCore
from rpc import RPCDispatcher

checks=[]

def ok(name, condition):
    assert condition, name
    checks.append(name)

core=AxvenCore()

summary=core.peer_health_summary()

ok("empty recovered zero",
   summary["recovered"] == 0)

ok("empty backoff active zero",
   summary["backoff_active"] == 0)

ok("empty never connected zero",
   summary["never_connected"] == 0)

recovered=("127.0.0.1",19001)
backoff=("127.0.0.1",19002)
fresh=("127.0.0.1",19003)
healthy=("127.0.0.1",19004)

for peer in (recovered,backoff,fresh,healthy):
    core.add_outbound_peer(peer)

# Previously failed, then successfully recovered.
core.peer_sync_successes[recovered]=2
core.peer_consecutive_failures[recovered]=0
core.peer_last_error[recovered]=None
core.peer_last_failure_at[recovered]="2026-08-15T18:00:00Z"
core.peer_last_success_at[recovered]="2026-08-15T18:01:00Z"
core.set_peer_retry_schedule(recovered,5.0,5.0)

# Currently unhealthy and in exponential backoff.
core.peer_sync_successes[backoff]=0
core.peer_consecutive_failures[backoff]=3
core.peer_last_error[backoff]="ConnectionRefusedError: offline"
core.peer_last_failure_at[backoff]="2026-08-15T18:02:00Z"
core.set_peer_retry_schedule(backoff,20.0,5.0)

# Configured but has never connected.
core.peer_sync_successes[fresh]=0
core.peer_consecutive_failures[fresh]=0
core.peer_last_error[fresh]=None
core.set_peer_retry_schedule(fresh,5.0,5.0)

# Healthy peer that has never failed.
core.peer_sync_successes[healthy]=4
core.peer_consecutive_failures[healthy]=0
core.peer_last_error[healthy]=None
core.peer_last_success_at[healthy]="2026-08-15T18:03:00Z"
core.set_peer_retry_schedule(healthy,5.0,5.0)

summary=core.peer_health_summary()

ok("four peers counted",
   summary["total"] == 4)

ok("one recovered peer counted",
   summary["recovered"] == 1)

ok("one active backoff counted",
   summary["backoff_active"] == 1)

ok("two never connected peers counted",
   summary["never_connected"] == 2)

ok("existing unhealthy semantics preserved",
   summary["unhealthy"] == 1)

ok("existing healthy semantics preserved",
   summary["healthy"] == 3)

rpc=RPCDispatcher(core)
rpc_summary=rpc.call("get_peer_health")

ok("RPC recovery summary matches core",
   rpc_summary == summary)

core.remove_outbound_peer(backoff)
summary=core.peer_health_summary()

ok("removed backoff peer clears backoff count",
   summary["backoff_active"] == 0)

ok("removed never-connected peer updates count",
   summary["never_connected"] == 1)

ok("recovered count survives unrelated removal",
   summary["recovered"] == 1)

print(
    f"Checkpoint 49 peer recovery summary: "
    f"{len(checks)}/{len(checks)} GREEN"
)
