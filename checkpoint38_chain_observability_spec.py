from pathlib import Path
import subprocess
import sys

checks = []

def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)

ops = Path("canonical_ops.py").read_text(encoding="utf-8")

# CLI parser surface
check("overview parser", 'sp.add_parser("overview")' in ops)
check("explorer parser", 'sp.add_parser("explorer")' in ops)
check("blocks parser", 'sp.add_parser("blocks")' in ops)
check("block parser", 'sp.add_parser("block")' in ops)
check("chain-config parser", 'sp.add_parser("chain-config")' in ops)

# RPC dispatch surface
check("overview RPC", '"get_overview"' in ops)
check("explorer RPC", '"get_explorer_summary"' in ops)
check("blocks RPC", '"get_recent_blocks"' in ops)
check("block RPC", '"get_block"' in ops)
check("chain-config RPC", '"get_chain_config"' in ops)

# Argument contracts
check("blocks limit", 'bl.add_argument("--limit",type=int,default=20)' in ops)
check("block id", 'bk.add_argument("id",help="block height or hash")' in ops)
check("blocks limit forwarded", '{"limit":a.limit}' in ops)
check("block id forwarded", '{"id":a.id}' in ops)

# Existing RPC/core contracts must already exist.
rpc = Path("rpc.py").read_text(encoding="utf-8")
core = Path("core.py").read_text(encoding="utf-8")

check("RPC overview exists", 'method == "get_overview"' in rpc)
check("RPC explorer exists", 'method == "get_explorer_summary"' in rpc)
check("RPC recent blocks exists", 'method == "get_recent_blocks"' in rpc)
check("RPC block exists", 'method == "get_block"' in rpc)
check("RPC chain config exists", 'method == "get_chain_config"' in rpc)

check("core block supports numeric height",
      "block_id.isdigit()" in core)

# Smoke-test argparse surface without requiring a running daemon.
help_text = subprocess.check_output(
    [sys.executable, "canonical_ops.py", "--help"],
    text=True,
    encoding="utf-8"
)

for command in ("overview", "explorer", "blocks", "block", "chain-config"):
    check(f"help exposes {command}", command in help_text)

print(
    f"Checkpoint 38 chain observability: "
    f"{len(checks)}/{len(checks)} GREEN"
)
