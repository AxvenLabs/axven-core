#!/usr/bin/env python3
"""Checkpoint 47 acceptance contract: peer retry observability."""

from datetime import datetime

from core import AxvenCore


checks=[]


def ok(name, condition):
    assert condition, name
    checks.append(name)


def valid_utc_timestamp(value):
    if not isinstance(value,str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
        return True
    except ValueError:
        return False


core=AxvenCore()
peer=("127.0.0.1",19001)

core.add_outbound_peer(peer)

status=core.outbound_peer_status()[0]

ok("new peer has no scheduled retry delay",
   status["retry_delay_seconds"] is None)

ok("new peer has no next retry timestamp",
   status["next_retry_at"] is None)

ok("new peer is not in active backoff",
   status["retry_backoff_active"] is False)


core.set_peer_retry_schedule(
    peer,
    delay_seconds=5.0,
    base_interval=5.0,
)

status=core.outbound_peer_status()[0]

ok("base retry delay observable",
   status["retry_delay_seconds"] == 5.0)

ok("base retry timestamp observable",
   valid_utc_timestamp(status["next_retry_at"]))

ok("base retry is not considered backoff",
   status["retry_backoff_active"] is False)


core.set_peer_retry_schedule(
    peer,
    delay_seconds=10.0,
    base_interval=5.0,
)

status=core.outbound_peer_status()[0]

ok("backoff retry delay observable",
   status["retry_delay_seconds"] == 10.0)

ok("backoff retry timestamp observable",
   valid_utc_timestamp(status["next_retry_at"]))

ok("doubled delay reports active backoff",
   status["retry_backoff_active"] is True)


core.set_peer_retry_schedule(
    peer,
    delay_seconds=60.0,
    base_interval=5.0,
)

status=core.outbound_peer_status()[0]

ok("capped retry delay observable",
   status["retry_delay_seconds"] == 60.0)

ok("capped retry remains active backoff",
   status["retry_backoff_active"] is True)


core.clear_peer_retry_schedule(peer)

status=core.outbound_peer_status()[0]

ok("clearing schedule removes delay",
   status["retry_delay_seconds"] is None)

ok("clearing schedule removes timestamp",
   status["next_retry_at"] is None)

ok("clearing schedule clears backoff flag",
   status["retry_backoff_active"] is False)


core.set_peer_retry_schedule(
    peer,
    delay_seconds=20.0,
    base_interval=5.0,
)

core.remove_outbound_peer(peer)

ok("removed peer retry runtime state cleared",
   peer not in core.peer_retry_delay_seconds
   and peer not in core.peer_next_retry_at
   and peer not in core.peer_retry_base_interval)


core.add_outbound_peer(peer)
status=core.outbound_peer_status()[0]

ok("re-added peer starts without retry schedule",
   status["retry_delay_seconds"] is None
   and status["next_retry_at"] is None
   and status["retry_backoff_active"] is False)


print(
    f"Checkpoint 47 peer retry observability: "
    f"{len(checks)}/{len(checks)} GREEN"
)
