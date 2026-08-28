#!/usr/bin/env python3
"""P2P-only transaction wire structure and string budgets for untrusted messages."""

MAX_P2P_TXID_CHARS = 64
MAX_P2P_RECIPIENT_CHARS = 128
MAX_P2P_TX_SCHEME_CHARS = 32
MAX_P2P_TX_AUTH_CHARS = 8192

_TX_TOP_LEVEL_FIELDS = {"inputs", "outputs", "coinbase_height"}
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


def _validate_tx_input_fields(raw_input):
    raw_scheme = raw_input.get("scheme", "")
    if type(raw_scheme) is not str:
        raise ValueError("tx input scheme must be string")
    scheme = raw_scheme or "ed25519"
    allowed = _TX_INPUT_FIELDS.get(scheme)
    if allowed is None:
        raise ValueError("unknown tx input scheme")
    if any(key not in allowed for key in raw_input):
        raise ValueError("unknown tx input field")


def validate_tx_string_bounds(raw_tx):
    if any(key not in _TX_TOP_LEVEL_FIELDS for key in raw_tx):
        raise ValueError("unknown tx field")
    if "inputs" not in raw_tx:
        raise ValueError("tx inputs required")
    if "outputs" not in raw_tx:
        raise ValueError("tx outputs required")
    for raw_input in raw_tx.get("inputs", []):
        if len(raw_input["prev_txid"]) > MAX_P2P_TXID_CHARS:
            raise ValueError("tx input prev_txid too long")
        if "scheme" in raw_input and len(raw_input["scheme"]) > MAX_P2P_TX_SCHEME_CHARS:
            raise ValueError("tx input scheme too long")
        for field in _TX_AUTH_FIELDS:
            if field in raw_input and len(raw_input[field]) > MAX_P2P_TX_AUTH_CHARS:
                raise ValueError(f"tx input {field} too long")
        _validate_tx_input_fields(raw_input)
    for raw_output in raw_tx.get("outputs", []):
        if len(raw_output["recipient"]) > MAX_P2P_RECIPIENT_CHARS:
            raise ValueError("tx output recipient too long")
