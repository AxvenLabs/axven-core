#!/usr/bin/env python3
"""Checkpoint 52 acceptance contract: bounded peer health history."""

from core import AxvenCore


checks=[]


def ok(name, condition):
    assert condition, name
    checks.append(name)


core=AxvenCore()
peer=("127.0.0.1",19001)

core.add_outbound_peer(peer)

ok(
    "new peer starts with empty health history",
    core.peer_health_history(peer) == [],
)


# never_connected -> offline
core.peer_last_error[peer]="ConnectionRefusedError: offline"
core.peer_consecutive_failures[peer]=1
core.peer_last_failure_at[peer]="2026-08-15T22:00:00Z"
core.set_peer_retry_schedule(peer,5.0,5.0)
core.record_peer_health_transition(peer)

history=core.peer_health_history(peer)

ok(
    "first transition creates one history entry",
    len(history) == 1,
)

ok(
    "first history entry records source state",
    history[0]["from_state"] == "never_connected",
)

ok(
    "first history entry records destination state",
    history[0]["to_state"] == "offline",
)

ok(
    "first history entry records timestamp",
    isinstance(history[0]["at"],str)
    and history[0]["at"].endswith("Z"),
)


# Same state must not create another history entry.
first_history=list(history)
core.record_peer_health_transition(peer)

ok(
    "unchanged state does not append history",
    core.peer_health_history(peer) == first_history,
)


# offline -> backoff
core.peer_consecutive_failures[peer]=2
core.set_peer_retry_schedule(peer,10.0,5.0)
core.record_peer_health_transition(peer)

history=core.peer_health_history(peer)

ok(
    "second transition appends history",
    len(history) == 2,
)

ok(
    "second transition records offline to backoff",
    history[-1]["from_state"] == "offline"
    and history[-1]["to_state"] == "backoff",
)


# backoff -> recovered
core.peer_last_error[peer]=None
core.peer_sync_successes[peer]=1
core.peer_consecutive_failures[peer]=0
core.peer_last_success_at[peer]="2026-08-15T22:01:00Z"
core.set_peer_retry_schedule(peer,5.0,5.0)
core.record_peer_health_transition(peer)

history=core.peer_health_history(peer)

ok(
    "recovery appends third history entry",
    len(history) == 3,
)

ok(
    "recovery history records backoff to recovered",
    history[-1]["from_state"] == "backoff"
    and history[-1]["to_state"] == "recovered",
)


# Returned history must be isolated from internal bookkeeping.
external=core.peer_health_history(peer)
external.append({
    "from_state":"fake",
    "to_state":"fake",
    "at":"fake",
})

ok(
    "returned history cannot mutate internal history",
    len(core.peer_health_history(peer)) == 3,
)


# Exercise the bounded-history contract.
limit=core.PEER_HEALTH_HISTORY_LIMIT

ok(
    "health history limit is positive",
    isinstance(limit,int) and limit > 0,
)

states=["offline","backoff"]

for i in range(limit+5):
    current=states[i % 2]

    core.peer_last_error[peer]="ConnectionRefusedError: offline"
    core.peer_consecutive_failures[peer]=(
        1 if current == "offline" else 2
    )
    core.set_peer_retry_schedule(
        peer,
        5.0 if current == "offline" else 10.0,
        5.0,
    )
    core.record_peer_health_transition(peer)

history=core.peer_health_history(peer)

ok(
    "health history is bounded",
    len(history) <= limit,
)

ok(
    "health history reaches configured bound",
    len(history) == limit,
)

ok(
    "newest transition remains in bounded history",
    history[-1]["to_state"] == core.peer_health_state(peer),
)

ok(
    "history entries have stable schema",
    all(
        set(entry) == {"from_state","to_state","at"}
        for entry in history
    ),
)


# Removal must clear history.
core.remove_outbound_peer(peer)

ok(
    "peer removal clears health history bookkeeping",
    peer not in core.peer_health_transition_history,
)

ok(
    "removed peer returns empty health history",
    core.peer_health_history(peer) == [],
)


print(
    f"Checkpoint 52 peer health history: "
    f"{len(checks)}/{len(checks)} GREEN"
)
