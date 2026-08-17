#!/usr/bin/env python3
"""SEC-014 deterministic atomic chain-read regression contract."""

import inspect
import sys
import threading

import axven
from core import AxvenCore


print("SEC-014 ATOMIC CHAIN READ CONTRACT")
print("=" * 60)


# ---------------------------------------------------------------------------
# Prepare a deterministic reorg:
#
# A: genesis -> A1 -> A2
# B: genesis -> B1 -> B2 -> B3 -> B4
#
# Feeding B1/B2 into A creates a side chain.
# Feeding B3 must trigger the heavier-chain reorg.
# ---------------------------------------------------------------------------

a = axven.Blockchain()
b = axven.Blockchain()

wa = axven.Wallet()
wb = axven.Wallet()

for _ in range(2):
    a.mine(wa.address)

for _ in range(4):
    b.mine(wb.address)

core = AxvenCore(chain=a)

assert a.tip.height == 2
assert b.tip.height == 4

for blk in b.blocks[1:3]:
    ok, status = a.add_block(blk)
    assert ok and status == "side-chain", (ok, status)


# ---------------------------------------------------------------------------
# Locate the second publication statement in the REAL _reorg_to source.
#
# Current vulnerable publication sequence:
#
#   self.utxo, self.blocks = tu, tblocks
#   self.total_issued, self.chainwork, self.undo = ...
#
# Python trace fires BEFORE executing the target line, therefore pausing at
# the second line means the first publication has already happened.
# ---------------------------------------------------------------------------

source_lines, start_line = inspect.getsourcelines(
    axven.Blockchain._reorg_to
)

target_line = None

for offset, line in enumerate(source_lines):
    if "self.total_issued, self.chainwork, self.undo =" in line:
        target_line = start_line + offset
        break

assert target_line is not None, (
    "SEC-014 instrumentation anchor not found"
)

print("publication pause line:", target_line)


writer_paused = threading.Event()
allow_writer = threading.Event()
reader_done = threading.Event()

writer_result = {}
writer_error = {}
reader_result = {}
reader_error = {}


def writer_trace(frame, event, arg):
    if (
        event == "line"
        and frame.f_code is axven.Blockchain._reorg_to.__code__
        and frame.f_lineno == target_line
    ):
        writer_paused.set()

        if not allow_writer.wait(timeout=5):
            raise RuntimeError(
                "SEC-014 test timed out waiting to resume writer"
            )

    return writer_trace


def writer():
    sys.settrace(writer_trace)

    try:
        writer_result["value"] = a.add_block(b.blocks[3])
    except Exception as exc:
        writer_error["value"] = exc
    finally:
        sys.settrace(None)


def reader():
    try:
        reader_result["status"] = core.status()

        # Capture the active block list observed at the same test point.
        reader_result["visible_blocks"] = list(a.blocks)

    except Exception as exc:
        reader_error["value"] = exc

    finally:
        reader_done.set()


tw = threading.Thread(target=writer)
tw.start()

assert writer_paused.wait(timeout=5), (
    "writer never reached SEC-014 publication window"
)

print("writer paused between chain-state publications")

tr = threading.Thread(target=reader)
tr.start()

# Critical assertion:
#
# A correctly synchronized reader MUST NOT finish while the writer is paused
# halfway through publishing a logical chain state.
#
# Current vulnerable code is expected to finish immediately -> RED.
reader_finished_mid_publication = reader_done.wait(timeout=0.75)

mid_status = reader_result.get("status")
mid_blocks = reader_result.get("visible_blocks")

if mid_status is not None and mid_blocks is not None:
    visible_work = sum(
        axven.work_of(block.target)
        for block in mid_blocks
    )

    print("mid-publication reader completed:", True)
    print("mid height:", mid_status["height"])
    print("mid chainwork:", mid_status["chainwork"])
    print("visible chainwork:", visible_work)

else:
    print(
        "mid-publication reader completed:",
        reader_finished_mid_publication,
    )


# Resume reorg and allow all threads to finish.
allow_writer.set()

tw.join(timeout=5)
tr.join(timeout=5)

assert not tw.is_alive(), "writer thread did not terminate"
assert not tr.is_alive(), "reader thread did not terminate"

assert not writer_error, writer_error
assert not reader_error, reader_error

print("-" * 60)
print("writer result:", writer_result.get("value"))
print("final height:", a.tip.height)
print("final tip matches B:", a.tip.hash() == b.blocks[3].hash())
print("final validate:", a.validate())


assert writer_result["value"] == (True, "reorg")
assert a.tip.hash() == b.blocks[3].hash()
assert a.validate()


if reader_finished_mid_publication:
    status = reader_result["status"]
    blocks = reader_result["visible_blocks"]

    visible_work = sum(
        axven.work_of(block.target)
        for block in blocks
    )

    print("=" * 60)
    print("RED CONFIRMED: reader escaped during partial reorg publication")
    print(
        "status chainwork:",
        status["chainwork"],
        "visible chainwork:",
        visible_work,
    )

    raise SystemExit(1)


# If a synchronization fix exists, the reader should only complete after the
# writer releases the state boundary.
status = reader_result["status"]
blocks = reader_result["visible_blocks"]

visible_work = sum(
    axven.work_of(block.target)
    for block in blocks
)

assert status["height"] == len(blocks) - 1
assert status["chainwork"] == visible_work

print("=" * 60)
print("GREEN: reader was blocked until atomic chain state became visible")
