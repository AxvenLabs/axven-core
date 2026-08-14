from pathlib import Path
#!/usr/bin/env python3
"""Checkpoint 37 - peer observability acceptance contract."""

from core import AxvenCore
from rpc import RPCDispatcher


checks = []


def ok(name, condition):
    assert condition, name
    checks.append(name)


class FakeCore:
    def __init__(self):
        self.calls = 0

    def outbound_peer_status(self):
        self.calls += 1
        return [
            {
                "host": "seed.axven.org",
                "port": 18444,
                "last_error": None,
            }
        ]


# RPC exposure
fake = FakeCore()
rpc = RPCDispatcher(fake)

result = rpc.call("get_peers")

ok("get_peers RPC exists", isinstance(result, list))
ok("get_peers delegates exactly once", fake.calls == 1)
ok("peer list contains one peer", len(result) == 1)
ok("peer host exposed", result[0]["host"] == "seed.axven.org")
ok("peer port exposed", result[0]["port"] == 18444)
ok("healthy peer exposes null last_error", result[0]["last_error"] is None)


# Core observability semantics without network activity
core = AxvenCore()

ok("initial outbound peer list empty", core.outbound_peer_status() == [])

core.add_outbound_peer(("seed.axven.org", 18444))
core.add_outbound_peer(("127.0.0.1", 19000))

peers = core.outbound_peer_status()

ok("configured peers observable", len(peers) == 2)
ok("first configured host preserved", peers[0]["host"] == "seed.axven.org")
ok("first configured port preserved", peers[0]["port"] == 18444)
ok("second configured host preserved", peers[1]["host"] == "127.0.0.1")
ok("second configured port preserved", peers[1]["port"] == 19000)
ok("new peer starts without error", peers[0]["last_error"] is None)
ok("second new peer starts without error", peers[1]["last_error"] is None)

core.peer_last_error[("seed.axven.org", 18444)] = "connection refused"

peers = core.outbound_peer_status()

ok("peer error becomes observable",
   peers[0]["last_error"] == "connection refused")
ok("peer error isolated from other peers",
   peers[1]["last_error"] is None)


# Contract scope guardrails
rpc_source = Path("rpc.py").read_text(encoding="utf-8")
cli_source = Path("canonical_ops.py").read_text(encoding="utf-8")

ok("RPC method wired to outbound_peer_status",
   '"get_peers"' in rpc_source and "outbound_peer_status()" in rpc_source)

ok("canonical peers parser exists",
   'add_parser("peers")' in cli_source)

ok("canonical peers command calls get_peers",
   '"get_peers"' in cli_source)

ok("peer observability remains exposed",
   'add_parser("peers")' in cli_source and '"get_peers"' in cli_source)


print(
    f"Checkpoint 37 peer observability: "
    f"{len(checks)}/{len(checks)} GREEN"
)
