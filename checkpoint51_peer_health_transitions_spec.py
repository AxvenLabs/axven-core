#!/usr/bin/env python3
"""Checkpoint 51 acceptance contract: peer health transitions."""

from core import AxvenCore

checks=[]

def ok(name, condition):
    assert condition, name
    checks.append(name)

def status(core, peer):
    for item in core.outbound_peer_status():
        if (item["host"],item["port"]) == peer:
            return item
    raise AssertionError(f"peer not found: {peer}")


core=AxvenCore()
peer=("127.0.0.1",19001)

core.add_outbound_peer(peer)

# Initial configured state.
item=status(core,peer)

ok(
    "new peer starts never connected",
    item["health_state"] == "never_connected",
)

ok(
    "new peer has no previous health state",
    item["previous_health_state"] is None,
)

ok(
    "new peer starts with zero transitions",
    item["health_transition_count"] == 0,
)

ok(
    "new peer has no transition timestamp",
    item["last_health_transition_at"] is None,
)


# never_connected -> offline
core.peer_last_error[peer]="ConnectionRefusedError: offline"
core.peer_consecutive_failures[peer]=1
core.peer_last_failure_at[peer]="2026-08-15T21:00:00Z"
core.set_peer_retry_schedule(peer,5.0,5.0)
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "failure transitions peer to offline",
    item["health_state"] == "offline",
)

ok(
    "offline transition remembers previous state",
    item["previous_health_state"] == "never_connected",
)

ok(
    "offline transition increments count",
    item["health_transition_count"] == 1,
)

first_transition_at=item["last_health_transition_at"]

ok(
    "offline transition records timestamp",
    isinstance(first_transition_at,str)
    and first_transition_at.endswith("Z"),
)


# Recording same state must be idempotent.
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "same health state does not increment transition count",
    item["health_transition_count"] == 1,
)

ok(
    "same health state preserves transition timestamp",
    item["last_health_transition_at"] == first_transition_at,
)


# offline -> backoff
core.peer_consecutive_failures[peer]=2
core.set_peer_retry_schedule(peer,10.0,5.0)
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "expanded retry transitions peer to backoff",
    item["health_state"] == "backoff",
)

ok(
    "backoff remembers offline as previous state",
    item["previous_health_state"] == "offline",
)

ok(
    "backoff increments transition count",
    item["health_transition_count"] == 2,
)


# backoff -> recovered
core.peer_last_error[peer]=None
core.peer_sync_successes[peer]=1
core.peer_consecutive_failures[peer]=0
core.peer_last_success_at[peer]="2026-08-15T21:01:00Z"
core.set_peer_retry_schedule(peer,5.0,5.0)
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "successful retry transitions peer to recovered",
    item["health_state"] == "recovered",
)

ok(
    "recovery remembers backoff as previous state",
    item["previous_health_state"] == "backoff",
)

ok(
    "recovery increments transition count",
    item["health_transition_count"] == 3,
)

ok(
    "recovery transition timestamp remains observable",
    isinstance(item["last_health_transition_at"],str)
    and item["last_health_transition_at"].endswith("Z"),
)


# Removal must clear transition bookkeeping.
core.remove_outbound_peer(peer)

ok(
    "peer removal clears tracked health state",
    peer not in core.peer_health_current_state,
)

ok(
    "peer removal clears previous health state",
    peer not in core.peer_previous_health_state,
)

ok(
    "peer removal clears transition count",
    peer not in core.peer_health_transition_count,
)

ok(
    "peer removal clears transition timestamp",
    peer not in core.peer_last_health_transition_at,
)


print(
    f"Checkpoint 51 peer health transitions: "
    f"{len(checks)}/{len(checks)} GREEN"
)
