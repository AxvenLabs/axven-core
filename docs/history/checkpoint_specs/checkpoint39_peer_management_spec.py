from pathlib import Path
from core import AxvenCore
from rpc import RPCDispatcher

checks = []

def ok(name, condition):
    assert condition, name
    checks.append(name)

# ------------------------------------------------------------
# Runtime peer registration through RPC
# ------------------------------------------------------------

core = AxvenCore()
rpc = RPCDispatcher(core)

ok("initial peer list empty",
   core.outbound_peer_status() == [])

added = rpc.call("add_peer", {
    "host": "127.0.0.1",
    "port": 19001,
})

ok("add_peer returns host",
   added["host"] == "127.0.0.1")

ok("add_peer returns port",
   added["port"] == 19001)

peers = core.outbound_peer_status()

ok("peer registered at runtime",
   len(peers) == 1)

ok("registered peer host preserved",
   peers[0]["host"] == "127.0.0.1")

ok("registered peer port preserved",
   peers[0]["port"] == 19001)

ok("registered peer starts healthy",
   peers[0]["last_error"] is None)

# Duplicate registration must remain idempotent.
rpc.call("add_peer", {
    "host": "127.0.0.1",
    "port": 19001,
})

ok("duplicate peer not duplicated",
   len(core.outbound_peer_status()) == 1)

# ------------------------------------------------------------
# Input validation
# ------------------------------------------------------------

try:
    rpc.call("add_peer", {
        "host": "127.0.0.1",
        "port": 0,
    })
    invalid_port_rejected = False
except ValueError:
    invalid_port_rejected = True

ok("invalid peer port rejected",
   invalid_port_rejected)

try:
    rpc.call("add_peer", {
        "host": "",
        "port": 19001,
    })
    empty_host_rejected = False
except ValueError:
    empty_host_rejected = True

ok("empty peer host rejected",
   empty_host_rejected)

# ------------------------------------------------------------
# sync_peers RPC delegation
# Avoid real network access by replacing the core method.
# ------------------------------------------------------------

class SyncCore:
    def __init__(self):
        self.calls = 0

    def sync_outbound_peers(self):
        self.calls += 1
        return [
            {
                "peer": "127.0.0.1:19001",
                "ok": True,
                "accepted": 3,
            }
        ]

sync_core = SyncCore()
sync_rpc = RPCDispatcher(sync_core)

sync_result = sync_rpc.call("sync_peers")

ok("sync_peers delegates once",
   sync_core.calls == 1)

ok("sync_peers returns list",
   isinstance(sync_result, list))

ok("sync result peer preserved",
   sync_result[0]["peer"] == "127.0.0.1:19001")

ok("sync result success preserved",
   sync_result[0]["ok"] is True)

ok("sync accepted count preserved",
   sync_result[0]["accepted"] == 3)

# ------------------------------------------------------------
# Source contract / scope guardrails
# ------------------------------------------------------------

rpc_source = Path("rpc.py").read_text(encoding="utf-8")
cli_source = Path("canonical_ops.py").read_text(encoding="utf-8")
core_source = Path("core.py").read_text(encoding="utf-8")

ok("add_peer RPC exists",
   'method == "add_peer"' in rpc_source)

ok("sync_peers RPC exists",
   'method == "sync_peers"' in rpc_source)

ok("add-peer CLI parser exists",
   'add_parser("add-peer")' in cli_source)

ok("sync-peers CLI parser exists",
   'add_parser("sync-peers")' in cli_source)

ok("CLI add-peer calls RPC",
   '"add_peer"' in cli_source)

ok("CLI sync-peers calls RPC",
   '"sync_peers"' in cli_source)

ok("existing core peer registration reused",
   "add_outbound_peer" in core_source)

ok("existing outbound sync reused",
   "sync_outbound_peers" in core_source)

ok("runtime peer management remains exposed",
   'add_parser("add-peer")' in cli_source
   and 'add_parser("sync-peers")' in cli_source)

print(
    f"Checkpoint 39 peer management: "
    f"{len(checks)}/{len(checks)} GREEN"
)
