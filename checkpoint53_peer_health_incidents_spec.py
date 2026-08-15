#!/usr/bin/env python3
"""Checkpoint 53 acceptance contract: peer health incident tracking."""

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

item=status(core,peer)

ok(
    "new peer has no active health incident",
    item["health_incident_active"] is False,
)

ok(
    "new peer has no incident start timestamp",
    item["health_incident_started_at"] is None,
)

ok(
    "new peer starts with zero incidents",
    item["health_incident_count"] == 0,
)

ok(
    "new peer has no completed incident",
    item["last_health_incident"] is None,
)


# never_connected -> offline starts an incident.
core.peer_last_error[peer]="ConnectionRefusedError: offline"
core.peer_consecutive_failures[peer]=1
core.peer_last_failure_at[peer]="2026-08-16T00:00:00Z"
core.set_peer_retry_schedule(peer,5.0,5.0)
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "offline transition opens health incident",
    item["health_incident_active"] is True,
)

ok(
    "first failure increments incident count",
    item["health_incident_count"] == 1,
)

started_at=item["health_incident_started_at"]

ok(
    "incident start timestamp is observable",
    isinstance(started_at,str) and started_at.endswith("Z"),
)


# offline -> backoff remains the same incident.
core.peer_consecutive_failures[peer]=2
core.set_peer_retry_schedule(peer,10.0,5.0)
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "backoff keeps incident active",
    item["health_incident_active"] is True,
)

ok(
    "backoff does not create second incident",
    item["health_incident_count"] == 1,
)

ok(
    "backoff preserves incident start timestamp",
    item["health_incident_started_at"] == started_at,
)


# backoff -> recovered closes the incident.
core.peer_last_error[peer]=None
core.peer_sync_successes[peer]=1
core.peer_consecutive_failures[peer]=0
core.peer_last_success_at[peer]="2026-08-16T00:01:00Z"
core.set_peer_retry_schedule(peer,5.0,5.0)
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "recovery closes active incident",
    item["health_incident_active"] is False,
)

ok(
    "closed incident clears active start timestamp",
    item["health_incident_started_at"] is None,
)

incident=item["last_health_incident"]

ok(
    "completed incident becomes observable",
    isinstance(incident,dict),
)

ok(
    "completed incident records opening state",
    incident["from_state"] == "never_connected",
)

ok(
    "completed incident records terminal unhealthy state",
    incident["last_unhealthy_state"] == "backoff",
)

ok(
    "completed incident records recovery state",
    incident["recovered_to"] == "recovered",
)

ok(
    "completed incident preserves start timestamp",
    incident["started_at"] == started_at,
)

ok(
    "completed incident records end timestamp",
    isinstance(incident["ended_at"],str)
    and incident["ended_at"].endswith("Z"),
)

ok(
    "completed incident records unhealthy transition count",
    incident["unhealthy_transitions"] == 2,
)


# A later failure must create a new incident.
core.peer_last_error[peer]="ConnectionRefusedError: offline again"
core.peer_consecutive_failures[peer]=1
core.peer_last_failure_at[peer]="2026-08-16T00:02:00Z"
core.set_peer_retry_schedule(peer,5.0,5.0)
core.record_peer_health_transition(peer)

item=status(core,peer)

ok(
    "later failure opens another incident",
    item["health_incident_active"] is True,
)

ok(
    "later failure increments incident count",
    item["health_incident_count"] == 2,
)


# Removal must clear incident bookkeeping.
core.remove_outbound_peer(peer)

ok(
    "peer removal clears incident active state",
    peer not in core.peer_health_incident_active,
)

ok(
    "peer removal clears incident start state",
    peer not in core.peer_health_incident_started_at,
)

ok(
    "peer removal clears incident count",
    peer not in core.peer_health_incident_count,
)

ok(
    "peer removal clears completed incident",
    peer not in core.peer_last_health_incident,
)


print(
    f"Checkpoint 53 peer health incidents: "
    f"{len(checks)}/{len(checks)} GREEN"
)
