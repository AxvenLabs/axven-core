from pathlib import Path
from core import AxvenCore
from rpc import RPCDispatcher

checks = []

def ok(name, condition):
    assert condition, name
    checks.append(name)

# Core behavior
core = AxvenCore()

core.add_outbound_peer(("127.0.0.1", 19001))
core.add_outbound_peer(("127.0.0.1", 19002))

ok("two peers registered", len(core.outbound_peer_status()) == 2)

core.peer_last_error[("127.0.0.1", 19001)] = "connection refused"

removed = core.remove_outbound_peer(("127.0.0.1", 19001))

ok("removed host preserved", removed["host"] == "127.0.0.1")
ok("removed port preserved", removed["port"] == 19001)
ok("existing peer removed", removed["removed"] is True)

peers = core.outbound_peer_status()

ok("peer list shrinks", len(peers) == 1)
ok("remaining peer preserved", peers[0]["port"] == 19002)
ok("removed peer error cleared",
   ("127.0.0.1", 19001) not in core.peer_last_error)

# Idempotent removal
again = core.remove_outbound_peer(("127.0.0.1", 19001))

ok("missing peer reports false", again["removed"] is False)
ok("remaining peer still present", len(core.outbound_peer_status()) == 1)

# Validation
try:
    core.remove_outbound_peer(("127.0.0.1", 0))
    bad_port = False
except ValueError:
    bad_port = True

ok("invalid port rejected", bad_port)

try:
    core.remove_outbound_peer(("", 19001))
    bad_host = False
except ValueError:
    bad_host = True

ok("empty host rejected", bad_host)

# RPC behavior
rpc_core = AxvenCore()
rpc_core.add_outbound_peer(("seed.axven.org", 18444))
rpc_core.peer_last_error[("seed.axven.org", 18444)] = "test error"

rpc = RPCDispatcher(rpc_core)

result = rpc.call("remove_peer", {
    "host": "seed.axven.org",
    "port": 18444,
})

ok("RPC removed true", result["removed"] is True)
ok("RPC host preserved", result["host"] == "seed.axven.org")
ok("RPC port preserved", result["port"] == 18444)
ok("RPC peer list updated", rpc_core.outbound_peer_status() == [])
ok("RPC error state cleared",
   ("seed.axven.org", 18444) not in rpc_core.peer_last_error)

# Source contracts
core_source = Path("core.py").read_text(encoding="utf-8")
rpc_source = Path("rpc.py").read_text(encoding="utf-8")
cli_source = Path("canonical_ops.py").read_text(encoding="utf-8")

ok("core remove method exists",
   "def remove_outbound_peer" in core_source)

ok("remove_peer RPC exists",
   'method == "remove_peer"' in rpc_source)

ok("RPC delegates removal",
   "remove_outbound_peer" in rpc_source)

ok("remove-peer CLI exists",
   'add_parser("remove-peer")' in cli_source)

ok("remove-peer host argument exists",
   'rpe.add_argument("host")' in cli_source)

ok("remove-peer port argument exists",
   'rpe.add_argument("port",type=int)' in cli_source)

ok("remove-peer CLI calls RPC",
   '"remove_peer"' in cli_source)

ok("add-peer remains available",
   'add_parser("add-peer")' in cli_source)

ok("sync-peers remains available",
   'add_parser("sync-peers")' in cli_source)

print(
    f"Checkpoint 40 peer removal: "
    f"{len(checks)}/{len(checks)} GREEN"
)
