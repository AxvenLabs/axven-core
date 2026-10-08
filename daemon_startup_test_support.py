"""Test-only synchronization before a daemon's first automatic peer sync.

The parent observes initial RPC state, then releases the real sync via stdin.
No production daemon entry point imports this module.
"""
from __future__ import annotations

import os
import sys
import threading
from unittest.mock import patch

import axven_core
from core import AxvenCore


def wait_for_release(read, timeout=15.0):
    done = threading.Event()
    result = []

    def receive():
        try:
            result.append(read())
        finally:
            done.set()

    threading.Thread(target=receive, daemon=True).start()
    if not done.wait(timeout):
        raise TimeoutError("test parent did not release initial daemon sync")
    if result != [b"1"]:
        raise RuntimeError("invalid initial daemon sync release")


def release_initial_sync(proc):
    proc.stdin.write(b"1")
    proc.stdin.flush()
    proc.stdin.close()


def gated_main():
    original = AxvenCore.sync_outbound_peers
    first = True

    def sync(core):
        nonlocal first
        if first:
            first = False
            wait_for_release(lambda: os.read(sys.stdin.fileno(), 1))
        return original(core)

    with patch.object(AxvenCore, "sync_outbound_peers", sync):
        axven_core.main()
