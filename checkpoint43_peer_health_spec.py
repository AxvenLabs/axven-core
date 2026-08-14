#!/usr/bin/env python3
"""Checkpoint 43 acceptance contract: outbound peer health tracking."""

from unittest.mock import patch
from core import AxvenCore

checks=[]

def ok(name, condition):
    assert condition, name
    checks.append(name)

core=AxvenCore()
peer=("127.0.0.1",19999)
core.add_outbound_peer(peer)

status=core.outbound_peer_status()[0]
ok("new peer starts with zero successes",
   status["sync_successes"] == 0)
ok("new peer starts with zero consecutive failures",
   status["consecutive_failures"] == 0)

with patch("p2p.sync_to_peer", side_effect=ConnectionRefusedError("offline")):
    r=core.sync_outbound_peers()
    ok("first failed sync reported", r[0]["ok"] is False)

status=core.outbound_peer_status()[0]
ok("first failure counted", status["consecutive_failures"] == 1)
ok("failed sync records error", status["last_error"] is not None)

with patch("p2p.sync_to_peer", side_effect=ConnectionRefusedError("offline")):
    core.sync_outbound_peers()

status=core.outbound_peer_status()[0]
ok("consecutive failures accumulate",
   status["consecutive_failures"] == 2)

with patch("p2p.sync_to_peer", return_value=0):
    r=core.sync_outbound_peers()
    ok("successful sync reported", r[0]["ok"] is True)

status=core.outbound_peer_status()[0]
ok("successful sync counted", status["sync_successes"] == 1)
ok("success resets consecutive failures",
   status["consecutive_failures"] == 0)
ok("success clears last error", status["last_error"] is None)

with patch("p2p.sync_to_peer", return_value=3):
    core.sync_outbound_peers()

status=core.outbound_peer_status()[0]
ok("success counter accumulates", status["sync_successes"] == 2)

removed=core.remove_outbound_peer(peer)
ok("peer removed", removed["removed"] is True)
ok("removed peer health state cleared",
   peer not in core.peer_sync_successes
   and peer not in core.peer_consecutive_failures
   and peer not in core.peer_last_error)

print(f"Checkpoint 43 peer health: {len(checks)}/{len(checks)} GREEN")
