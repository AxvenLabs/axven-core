#!/usr/bin/env python3
"""Checkpoint 46: bounded per-peer retry/backoff contract."""

from core import AxvenCore

checks=[]

def ok(name, cond):
    assert cond, name
    checks.append(name)

core=AxvenCore()

peer1=("127.0.0.1",19001)
peer2=("127.0.0.1",19002)

core.add_outbound_peer(peer1)
core.add_outbound_peer(peer2)

base=5.0
cap=60.0

ok("healthy peer uses base interval",
   core.peer_retry_delay(peer1,base,cap) == 5.0)

core.peer_consecutive_failures[peer1]=1
ok("first failure retains base interval",
   core.peer_retry_delay(peer1,base,cap) == 5.0)

core.peer_consecutive_failures[peer1]=2
ok("second failure doubles retry interval",
   core.peer_retry_delay(peer1,base,cap) == 10.0)

core.peer_consecutive_failures[peer1]=3
ok("third failure doubles again",
   core.peer_retry_delay(peer1,base,cap) == 20.0)

core.peer_consecutive_failures[peer1]=4
ok("fourth failure reaches forty seconds",
   core.peer_retry_delay(peer1,base,cap) == 40.0)

core.peer_consecutive_failures[peer1]=5
ok("retry delay is capped",
   core.peer_retry_delay(peer1,base,cap) == 60.0)

core.peer_consecutive_failures[peer1]=20
ok("large failure count remains capped",
   core.peer_retry_delay(peer1,base,cap) == 60.0)

core.peer_consecutive_failures[peer2]=0
ok("one unhealthy peer does not backoff another",
   core.peer_retry_delay(peer2,base,cap) == 5.0)

core.peer_consecutive_failures[peer1]=0
ok("successful recovery restores base interval",
   core.peer_retry_delay(peer1,base,cap) == 5.0)

core.peer_consecutive_failures[peer1]=2
ok("test interval scales correctly",
   core.peer_retry_delay(peer1,0.5,60.0) == 1.0)

core.peer_consecutive_failures[peer1]=0
ok("minimum base interval enforced",
   core.peer_retry_delay(peer1,0.1,60.0) == 0.5)

ok("cap cannot reduce effective base",
   core.peer_retry_delay(peer1,5.0,1.0) == 5.0)

print(
    f"Checkpoint 46 peer retry backoff: "
    f"{len(checks)}/{len(checks)} GREEN"
)
