#!/usr/bin/env python3
"""Regressions for daemon startup observation and SEC-132 fixture transport."""
import threading
import unittest
from unittest.mock import patch

import daemon_startup_test_support as gate
import p2p
import security_sec132_p2p_json_preparse_complexity_spec as transport


class ValidationFixtureTests(unittest.TestCase):
    def test_release_requires_exact_parent_signal(self):
        gate.wait_for_release(lambda: b"1")
        for value in (b"", b"0"):
            with self.assertRaises(RuntimeError):
                gate.wait_for_release(lambda: value)

    def test_missing_parent_release_is_bounded(self):
        release = threading.Event()
        def read():
            release.wait(1)
            return b"1"
        try:
            with self.assertRaises(TimeoutError):
                gate.wait_for_release(read, timeout=0.01)
        finally:
            release.set()

    def test_gate_precedes_real_sync_and_only_blocks_first_call(self):
        order = []
        def real_sync(core):
            order.append("sync")
            return "real-result"
        def main():
            for _ in range(2):
                self.assertEqual(gate.AxvenCore.sync_outbound_peers(object()), "real-result")
        with patch.object(gate.AxvenCore, "sync_outbound_peers", real_sync), patch.object(
            gate, "wait_for_release", side_effect=lambda read: order.append("release")
        ), patch.object(gate.axven_core, "main", main):
            gate.gated_main()
            self.assertIs(gate.AxvenCore.sync_outbound_peers, real_sync)
        self.assertEqual(order, ["release", "sync", "sync"])

    def small_buffer_pair(self):
        left, right = self.original_pair()
        left.setsockopt(transport.socket.SOL_SOCKET, transport.socket.SO_SNDBUF, 4096)
        return left, right

    def test_large_valid_frame_drains_small_send_buffer(self):
        self.original_pair = transport.socket.socketpair
        raw = b'{"type":"get_status","padding":"' + b"x" * (256 * 1024) + b'"}'
        with patch.object(transport.socket, "socketpair", self.small_buffer_pair):
            value = transport.recv_raw(raw)
        self.assertEqual(value["type"], "get_status")
        self.assertEqual(len(value["padding"]), 256 * 1024)

    def test_large_rejected_frame_keeps_parser_gate_and_releases_budget(self):
        self.original_pair = transport.socket.socketpair
        raw = transport.flat_array(p2p.MAX_P2P_JSON_STRUCTURAL_ITEMS + 1)
        budget = p2p._InboundFrameByteBudget()
        with patch.object(transport.socket, "socketpair", self.small_buffer_pair), patch.object(
            p2p.json, "loads", side_effect=AssertionError("parser must not run")
        ) as parser:
            with self.assertRaisesRegex(p2p.ProtocolError, "structural complexity exceeded"):
                transport.recv_raw(raw, budget=budget)
            parser.assert_not_called()
        self.assertEqual(budget.snapshot()["inflight_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
