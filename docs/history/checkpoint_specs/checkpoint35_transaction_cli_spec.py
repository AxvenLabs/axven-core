#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
OPS = ROOT / "canonical_ops.py"

checks = []

def ok(name, cond):
    assert cond, name
    checks.append(name)

src = OPS.read_text(encoding="utf-8")

# Parser surface
ok("addresses command", 'sp.add_parser("addresses")' in src)
ok("mempool command", 'sp.add_parser("mempool")' in src)
ok("tx command", 'sp.add_parser("tx")' in src)
ok("send command", 'sp.add_parser("send")' in src)

# RPC wiring
ok("addresses RPC", '"get_addresses"' in src)
ok("mempool RPC", '"get_mempool"' in src)
ok("transaction RPC", '"get_transaction"' in src)
ok("send RPC", '"send"' in src)

# Send parameters
ok("input scheme parameter", '"input_scheme":a.scheme' in src)
ok("recipient parameter", '"recipient":a.recipient' in src)
ok("amount parameter", '"amount":a.amount' in src)
ok("fee parameter", '"fee":a.fee' in src)

# CLI behavior that does not require a running node
help_out = subprocess.run(
    [sys.executable, str(OPS), "--help"],
    capture_output=True,
    text=True,
    check=True,
).stdout

for command in ("addresses", "mempool", "tx", "send"):
    ok(f"{command} visible in help", command in help_out)

send_help = subprocess.run(
    [sys.executable, str(OPS), "send", "--help"],
    capture_output=True,
    text=True,
    check=True,
).stdout

ok("send recipient positional", "recipient" in send_help)
ok("send amount positional", "amount" in send_help)
ok("send fee option", "--fee" in send_help)
ok("send scheme option", "--scheme" in send_help)
ok("send rpc port option", "--rpc-port" in send_help)

print(f"Checkpoint 35 transaction CLI spec: {len(checks)}/{len(checks)} GREEN")
