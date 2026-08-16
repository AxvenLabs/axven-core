#!/usr/bin/env python3
"""Checkpoint 54 acceptance contract: bounded peer health incident history."""

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


def open_incident(core, peer, failure_at):
    core.peer_last_error[peer]="ConnectionRefusedError: offline"
    core.peer_consecutive_failures[peer]=1
    core.peer_last_failure_at[peer]=failure_at
    core.set_peer_retry_schedule(peer,5.0,5.0)
    core.record_peer_health_transition(peer)


def enter_backoff(core, peer):
    core.peer_consecutive_failures[peer]=2
    core.set_peer_retry_schedule(peer,10.0,5.0)
    core.record_peer_health_transition(peer)


def recover(core, peer, success_at):
    core.peer_last_error[peer]=None
    core.peer_sync_successes[peer]=(
        core.peer_sync_successes.get(peer,0)+1
    )
    core.peer_consecutive_failures[peer]=0
    core.peer_last_success_at[peer]=success_at
    core.set_peer_retry_schedule(peer,5.0,5.0)
    core.record_peer_health_transition(peer)


core=AxvenCore()
peer=("127.0.0.1",19001)

core.add_outbound_peer(peer)

ok(
    "new peer starts with empty incident history",
    core.peer_health_incident_history(peer) == [],
)

item=status(core,peer)

ok(
    "new peer exposes empty incident history",
    item["health_incident_history"] == [],
)


# Incident 1.
open_incident(core,peer,"2026-08-16T08:00:00Z")
enter_backoff(core,peer)
recover(core,peer,"2026-08-16T08:01:00Z")

history=core.peer_health_incident_history(peer)

ok(
    "first completed incident enters history",
    len(history) == 1,
)

ok(
    "first incident history matches last incident",
    history[-1] == status(core,peer)["last_health_incident"],
)

ok(
    "first incident records full unhealthy lifecycle",
    history[-1]["from_state"] == "never_connected"
    and history[-1]["last_unhealthy_state"] == "backoff"
    and history[-1]["recovered_to"] == "recovered"
    and history[-1]["unhealthy_transitions"] == 2,
)


# Incident 2.
open_incident(core,peer,"2026-08-16T08:02:00Z")
second_started=status(core,peer)["health_incident_started_at"]
recover(core,peer,"2026-08-16T08:03:00Z")

history=core.peer_health_incident_history(peer)

ok(
    "second completed incident appends history",
    len(history) == 2,
)

ok(
    "incident history preserves completion order",
    history[0]["unhealthy_transitions"] == 2
    and history[1]["started_at"] == second_started,
)

ok(
    "latest history entry matches last incident",
    history[-1] == status(core,peer)["last_health_incident"],
)


# Defensive-copy contract.
external=core.peer_health_incident_history(peer)
external[0]["from_state"]="fake"
external.append({"fake":True})

internal=core.peer_health_incident_history(peer)

ok(
    "returned incident history cannot mutate internal history",
    len(internal) == 2
    and internal[0]["from_state"] != "fake",
)


# Bounded-history contract.
limit=core.PEER_HEALTH_INCIDENT_HISTORY_LIMIT

ok(
    "incident history limit is positive",
    isinstance(limit,int) and limit > 0,
)

for i in range(limit+5):
    open_incident(
        core,
        peer,
        f"2026-08-16T09:{i % 60:02d}:00Z",
    )
    recover(
        core,
        peer,
        f"2026-08-16T10:{i % 60:02d}:00Z",
    )

history=core.peer_health_incident_history(peer)

ok(
    "incident history is bounded",
    len(history) <= limit,
)

ok(
    "incident history fills configured bound",
    len(history) == limit,
)

ok(
    "newest completed incident remains in bounded history",
    history[-1] == status(core,peer)["last_health_incident"],
)

ok(
    "incident history entries have stable schema",
    all(
        set(entry) == {
            "from_state",
            "last_unhealthy_state",
            "recovered_to",
            "started_at",
            "ended_at",
            "unhealthy_transitions",
        }
        for entry in history
    ),
)


# Removal must clear incident history bookkeeping.
core.remove_outbound_peer(peer)

ok(
    "peer removal clears incident history bookkeeping",
    peer not in core.peer_health_incident_history_entries,
)

ok(
    "removed peer returns empty incident history",
    core.peer_health_incident_history(peer) == [],
)


print(
    f"Checkpoint 54 peer health incident history: "
    f"{len(checks)}/{len(checks)} GREEN"
)
