#!/usr/bin/env python3
"""P2P-only transaction string budgets for untrusted wire messages."""

MAX_P2P_TXID_CHARS = 64
MAX_P2P_RECIPIENT_CHARS = 128


def validate_tx_string_bounds(raw_tx):
    for raw_input in raw_tx.get("inputs", []):
        if len(raw_input["prev_txid"]) > MAX_P2P_TXID_CHARS:
            raise ValueError("tx input prev_txid too long")
    for raw_output in raw_tx.get("outputs", []):
        if len(raw_output["recipient"]) > MAX_P2P_RECIPIENT_CHARS:
            raise ValueError("tx output recipient too long")
