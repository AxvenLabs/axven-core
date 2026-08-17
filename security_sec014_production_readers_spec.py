#!/usr/bin/env python3
"""SEC-014 production reader boundary regression contract."""

import inspect
import sys
import threading
import time

import axven
import p2p
import wallet
from core import AxvenCore


print("SEC-014 PRODUCTION READER BOUNDARY CONTRACT")
print("=" * 68)


# ---------------------------------------------------------------------------
# Build deterministic reorg fixture.
# ---------------------------------------------------------------------------

a = axven.Blockchain()
b = axven.Blockchain()

wa = axven.Wallet()
wb = axven.Wallet()

for _ in range(2):
    a.mine(wa.address)

for _ in range(4):
    b.mine(wb.address)

identity = wallet.WalletIdentity(
    ed_keypair=(wa.public_key, wa.private_key)
)

core = AxvenCore(chain=a, identity=identity)
session = p2p.PeerSession(a, core.mempool)

for blk in b.blocks[1:3]:
    ok, status = a.add_block(blk)
    assert ok and status == "side-chain", (ok, status)


# ---------------------------------------------------------------------------
# Pause real _reorg_to between publication statements.
# ---------------------------------------------------------------------------

source_lines, start_line = inspect.getsourcelines(
    axven.Blockchain._reorg_to
)

target_line = None

for offset, line in enumerate(source_lines):
    if "self.total_issued, self.chainwork, self.undo =" in line:
        target_line = start_line + offset
        break

assert target_line is not None

writer_paused = threading.Event()
allow_writer = threading.Event()

writer_result = {}
writer_error = {}


def trace_writer(frame, event, arg):
    if (
        event == "line"
        and frame.f_code is axven.Blockchain._reorg_to.__code__
        and frame.f_lineno == target_line
    ):
        writer_paused.set()

        if not allow_writer.wait(timeout=10):
            raise RuntimeError("writer resume timeout")

    return trace_writer


def writer():
    sys.settrace(trace_writer)

    try:
        writer_result["value"] = a.add_block(b.blocks[3])
    except Exception as exc:
        writer_error["value"] = exc
    finally:
        sys.settrace(None)


tw = threading.Thread(target=writer)
tw.start()

assert writer_paused.wait(timeout=5), (
    "writer never reached partial publication window"
)

print("writer paused between reorg publication statements")


# ---------------------------------------------------------------------------
# Every listed production reader must BLOCK while writer owns state boundary.
# ---------------------------------------------------------------------------

readers = {
    "core.status": lambda: core.status(),
    "core.recent_blocks": lambda: core.recent_blocks(10),
    "core.get_block": lambda: core.get_block(0),
    "core.get_transaction": lambda: core.get_transaction("f" * 64),
    "core.explorer_summary": lambda: core.explorer_summary(),
    "core.balance": lambda: core.balance(),
    "core.wallet_status": lambda: core.wallet_status(),
    "core.list_unspent": lambda: core.list_unspent(axven.SCHEME_ED25519),
    "chain.balance": lambda: a.balance(wa.address),
    "chain.spendable": lambda: a.spendable(wa.address),
    "p2p.status": lambda: session.status(),
    "p2p.locator": lambda: session.locator(),
    "p2p.get_blocks": lambda: session.handle({
        "type": "get_blocks",
        "locator": [],
        "limit": 2,
    }),
}

done = {}
values = {}
errors = {}
threads = {}


def run_reader(name, fn):
    try:
        values[name] = fn()
    except KeyError as exc:
        # get_transaction(random missing txid) is expected to end in KeyError
        # AFTER the chain-state lock becomes available.
        values[name] = f"expected KeyError: {exc}"
    except Exception as exc:
        errors[name] = exc
    finally:
        done[name].set()


for name, fn in readers.items():
    done[name] = threading.Event()

    t = threading.Thread(
        target=run_reader,
        args=(name, fn),
        daemon=True,
    )

    threads[name] = t
    t.start()


# Give every reader a fair chance to run.
time.sleep(0.75)

escaped = [
    name
    for name, event in done.items()
    if event.is_set()
]

print("readers completed during partial publication:", escaped)

if escaped:
    allow_writer.set()

    for t in threads.values():
        t.join(timeout=5)

    tw.join(timeout=5)

    print("=" * 68)
    print(
        "RED: production reader escaped while reorg state was partially "
        "published"
    )
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Release writer. All readers must then finish normally.
# ---------------------------------------------------------------------------

allow_writer.set()

tw.join(timeout=5)

for t in threads.values():
    t.join(timeout=10)

assert not tw.is_alive(), "writer did not terminate"
assert not writer_error, writer_error

unfinished = [
    name
    for name, t in threads.items()
    if t.is_alive()
]

assert not unfinished, f"reader threads did not finish: {unfinished}"
assert not errors, {
    name: f"{type(exc).__name__}: {exc}"
    for name, exc in errors.items()
}

assert writer_result["value"] == (True, "reorg")
assert a.tip.hash() == b.blocks[3].hash()
assert a.validate()

print("-" * 68)

for name in readers:
    print(f"[GREEN] {name} blocked until coherent chain state")

print("-" * 68)
print("final height:", a.tip.height)
print("final validate:", a.validate())
print(
    f"SEC-014 production reader boundary: "
    f"{len(readers)}/{len(readers)} GREEN"
)
