#!/usr/bin/env python3
"""Checkpoint 50 acceptance contract: peer health classification."""

from core import AxvenCore

checks=[]

def ok(name, condition):
    assert condition, name
    checks.append(name)

def state(core, peer):
    for item in core.outbound_peer_status():
        if (item["host"],item["port"]) == peer:
            return item["health_state"]
    raise AssertionError(f"peer not found: {peer}")


core=AxvenCore()

never=("127.0.0.1",19001)
offline=("127.0.0.1",19002)
backoff=("127.0.0.1",19003)
healthy=("127.0.0.1",19004)
recovered=("127.0.0.1",19005)

for peer in (never,offline,backoff,healthy,recovered):
    core.add_outbound_peer(peer)


# Configured but never attempted/succeeded.
ok(
    "new peer classified never connected",
    state(core,never) == "never_connected",
)


# Failed before any successful synchronization.
core.peer_last_error[offline]="ConnectionRefusedError: offline"
core.peer_consecutive_failures[offline]=1
core.peer_last_failure_at[offline]="2026-08-15T20:00:00Z"
core.set_peer_retry_schedule(offline,5.0,5.0)

ok(
    "failed peer classified offline",
    state(core,offline) == "offline",
)


# Same failure state, but exponential retry backoff is active.
core.peer_last_error[backoff]="ConnectionRefusedError: offline"
core.peer_consecutive_failures[backoff]=2
core.peer_last_failure_at[backoff]="2026-08-15T20:00:00Z"
core.set_peer_retry_schedule(backoff,10.0,5.0)

ok(
    "backing off peer classified backoff",
    state(core,backoff) == "backoff",
)


# Successful peer with no historical failure.
core.peer_last_error[healthy]=None
core.peer_sync_successes[healthy]=3
core.peer_consecutive_failures[healthy]=0
core.peer_last_success_at[healthy]="2026-08-15T20:01:00Z"
core.set_peer_retry_schedule(healthy,5.0,5.0)

ok(
    "successful peer classified healthy",
    state(core,healthy) == "healthy",
)


# Successful peer that previously failed.
core.peer_last_error[recovered]=None
core.peer_sync_successes[recovered]=2
core.peer_consecutive_failures[recovered]=0
core.peer_last_failure_at[recovered]="2026-08-15T20:00:00Z"
core.peer_last_success_at[recovered]="2026-08-15T20:02:00Z"
core.set_peer_retry_schedule(recovered,5.0,5.0)

ok(
    "recovered peer classified recovered",
    state(core,recovered) == "recovered",
)


statuses={
    (item["host"],item["port"]):item
    for item in core.outbound_peer_status()
}

ok(
    "classification exposed in peer status",
    all("health_state" in item for item in statuses.values()),
)

ok(
    "classification preserves retry observability",
    statuses[backoff]["retry_backoff_active"] is True
    and statuses[backoff]["retry_delay_seconds"] == 10.0,
)

ok(
    "classification preserves failure counters",
    statuses[offline]["consecutive_failures"] == 1
    and statuses[backoff]["consecutive_failures"] == 2,
)

ok(
    "classification preserves success counters",
    statuses[healthy]["sync_successes"] == 3
    and statuses[recovered]["sync_successes"] == 2,
)

ok(
    "classification preserves timestamps",
    statuses[recovered]["last_failure_at"] is not None
    and statuses[recovered]["last_success_at"] is not None,
)

print(
    f"Checkpoint 50 peer health classification: "
    f"{len(checks)}/{len(checks)} GREEN"
)
