#!/usr/bin/env python3
"""Checkpoint 41 acceptance contract: persistent outbound peer configuration."""

import tempfile
from pathlib import Path

from datadir import DataDir
from rpc import RPCDispatcher


checks = []


def ok(name, condition):
    assert condition, name
    checks.append(name)


with tempfile.TemporaryDirectory() as td:
    dd = DataDir(td)

    ok("peer config path belongs to datadir",
       dd.peer_file == Path(td).resolve() / "peers.json")

    ok("missing peer config loads empty",
       dd.load_peers() == [])

    dd.save_peers([
        ("seed.axven.org", 18444),
        ("127.0.0.1", 19000),
    ])

    ok("peer config file created",
       dd.peer_file.exists())

    peers = dd.load_peers()

    ok("saved peer count restored",
       len(peers) == 2)

    ok("first peer restored exactly",
       peers[0] == ("seed.axven.org", 18444))

    ok("second peer restored exactly",
       peers[1] == ("127.0.0.1", 19000))

    core = dd.load_core()

    ok("load_core restores persisted peers",
       core.outbound_peers == [
           ("seed.axven.org", 18444),
           ("127.0.0.1", 19000),
       ])

    core.remove_outbound_peer(("seed.axven.org", 18444))

    ok("core removal automatically persists",
       dd.load_peers() == [("127.0.0.1", 19000)])

    restarted = dd.load_core()

    ok("removed peer stays removed after restart",
       ("seed.axven.org", 18444) not in restarted.outbound_peers)

    ok("remaining peer survives restart",
       restarted.outbound_peers == [("127.0.0.1", 19000)])

    restarted.add_outbound_peer(("example.org", 18444))

    ok("core addition automatically persists",
       ("example.org", 18444) in dd.load_peers())

    restarted_again = dd.load_core()

    ok("new peer survives second restart",
       ("example.org", 18444) in restarted_again.outbound_peers)

    ok("peer runtime error state is not persisted",
       restarted_again.peer_last_error == {})

    rpc = RPCDispatcher(restarted_again)

    added = rpc.call("add_peer", {
        "host": "rpc-peer.example",
        "port": 18444,
    })

    ok("RPC add_peer succeeds",
       added == {"host": "rpc-peer.example", "port": 18444})

    rpc_restart = dd.load_core()

    ok("RPC-added peer survives restart",
       ("rpc-peer.example", 18444) in rpc_restart.outbound_peers)

    rpc2 = RPCDispatcher(rpc_restart)

    removed = rpc2.call("remove_peer", {
        "host": "rpc-peer.example",
        "port": 18444,
    })

    ok("RPC remove_peer succeeds",
       removed["removed"] is True)

    final_restart = dd.load_core()

    ok("RPC-removed peer stays removed after restart",
       ("rpc-peer.example", 18444) not in final_restart.outbound_peers)


print(
    f"Checkpoint 41 peer persistence: "
    f"{len(checks)}/{len(checks)} GREEN"
)
