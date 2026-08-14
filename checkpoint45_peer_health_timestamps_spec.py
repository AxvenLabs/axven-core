#!/usr/bin/env python3
"""Checkpoint 45 acceptance contract: peer health timestamps."""

from datetime import datetime
from unittest.mock import patch

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
peer=("127.0.0.1",19999)
core.add_outbound_peer(peer)

status=core.outbound_peer_status()[0]

ok("new peer has no success timestamp",
   status["last_success_at"] is None)

ok("new peer has no failure timestamp",
   status["last_failure_at"] is None)


with patch("p2p.sync_to_peer",side_effect=ConnectionRefusedError("offline")):
    core.sync_outbound_peers()

status=core.outbound_peer_status()[0]
failure_at=status["last_failure_at"]

ok("failure creates timestamp",
   valid_utc_timestamp(failure_at))

ok("failure does not create success timestamp",
   status["last_success_at"] is None)


with patch("p2p.sync_to_peer",return_value=0):
    core.sync_outbound_peers()

status=core.outbound_peer_status()[0]
success_at=status["last_success_at"]

ok("success creates timestamp",
   valid_utc_timestamp(success_at))

ok("historical failure timestamp retained after recovery",
   status["last_failure_at"] == failure_at)

ok("successful recovery clears last error",
   status["last_error"] is None)

ok("successful recovery resets consecutive failures",
   status["consecutive_failures"] == 0)


core.remove_outbound_peer(peer)

ok("removed peer success timestamp cleared",
   peer not in core.peer_last_success_at)

ok("removed peer failure timestamp cleared",
   peer not in core.peer_last_failure_at)


core.add_outbound_peer(peer)
status=core.outbound_peer_status()[0]

ok("re-added peer starts without success timestamp",
   status["last_success_at"] is None)

ok("re-added peer starts without failure timestamp",
   status["last_failure_at"] is None)


print(
    f"Checkpoint 45 peer health timestamps: "
    f"{len(checks)}/{len(checks)} GREEN"
)
