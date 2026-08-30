#!/usr/bin/env python3
"""P2P-only transaction wire structure and string budgets for untrusted messages."""

MAX_P2P_TXID_CHARS = 64
MAX_P2P_RECIPIENT_CHARS = 128
MAX_P2P_TX_SCHEME_CHARS = 32
MAX_P2P_TX_AUTH_CHARS = 8192

_NULL_TXID = "0" * 64
_COINBASE_INDEX = 0xFFFFFFFF
_TX_TOP_LEVEL_FIELDS = {"inputs", "outputs", "coinbase_height"}
_TX_OUTPUT_FIELDS = {"amount", "recipient"}
_TX_INPUT_FIELDS = {
    "ed25519": {"prev_txid", "index", "signature", "public_key"},
    "ml-dsa-44": {"prev_txid", "index", "scheme", "signature", "public_key"},
    "hybrid-ed25519+ml-dsa-44": {
        "prev_txid",
        "index",
        "scheme",
        "ed_signature",
        "ed_public_key",
        "ml_signature",
        "ml_public_key",
    },
}

_TX_AUTH_FIELDS = (
    "signature",
    "public_key",
    "ed_signature",
    "ed_public_key",
    "ml_signature",
    "ml_public_key",
)


def _is_wire_coinbase(raw_tx):
    inputs = raw_tx.get("inputs", [])
    return (
        len(inputs) == 1
        and inputs[0].get("prev_txid") == _NULL_TXID
        and inputs[0].get("index") == _COINBASE_INDEX
    )


def _validate_tx_input_fields(raw_input, *, coinbase=False):
    if coinbase:
        # The historical canonical serializer emits the legacy Ed25519 witness
        # slots as empty strings for coinbase. Preserve that exact wire shape,
        # but never allow attacker-controlled witness material to hide behind a
        # coinbase txid that does not commit to it.
        required = {"prev_txid", "index", "signature", "public_key"}
        if set(raw_input) != required:
            raise ValueError("non-canonical coinbase input fields")
        if raw_input["signature"] != "" or raw_input["public_key"] != "":
            raise ValueError("coinbase witness fields must be empty")
        return

    raw_scheme = raw_input.get("scheme", "")
    if type(raw_scheme) is not str:
        raise ValueError("tx input scheme must be string")
    scheme = raw_scheme or "ed25519"
    required = _TX_INPUT_FIELDS.get(scheme)
    if required is None:
        raise ValueError("unknown tx input scheme")
    if set(raw_input) != required:
        raise ValueError("non-canonical tx input fields")


def validate_tx_string_bounds(raw_tx):
    if any(key not in _TX_TOP_LEVEL_FIELDS for key in raw_tx):
        raise ValueError("unknown tx field")
    if "inputs" not in raw_tx:
        raise ValueError("tx inputs required")
    if "outputs" not in raw_tx:
        raise ValueError("tx outputs required")

    coinbase = _is_wire_coinbase(raw_tx)
    if coinbase:
        if "coinbase_height" not in raw_tx:
            raise ValueError("coinbase height required")
    elif "coinbase_height" in raw_tx:
        raise ValueError("coinbase height forbidden on regular tx")

    for raw_input in raw_tx.get("inputs", []):
        if len(raw_input["prev_txid"]) > MAX_P2P_TXID_CHARS:
            raise ValueError("tx input prev_txid too long")
        if "scheme" in raw_input and len(raw_input["scheme"]) > MAX_P2P_TX_SCHEME_CHARS:
            raise ValueError("tx input scheme too long")
        for field in _TX_AUTH_FIELDS:
            if field in raw_input and len(raw_input[field]) > MAX_P2P_TX_AUTH_CHARS:
                raise ValueError(f"tx input {field} too long")
        _validate_tx_input_fields(raw_input, coinbase=coinbase)

    for raw_output in raw_tx.get("outputs", []):
        if set(raw_output) != _TX_OUTPUT_FIELDS:
            raise ValueError("non-canonical tx output fields")
        if len(raw_output["recipient"]) > MAX_P2P_RECIPIENT_CHARS:
            raise ValueError("tx output recipient too long")
