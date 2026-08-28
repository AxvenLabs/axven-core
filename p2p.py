#!/usr/bin/env python3
"""Axven P2P transport — checkpoint 4.

Length-prefixed JSON framing, identity-bound handshake, tx/block propagation,
orphan-safe block acceptance, and locator-based active-chain sync.
"""
from __future__ import annotations
import json, socket, struct, threading, time
from collections import OrderedDict
from typing import Any, Dict, Optional
import axven
from p2p_tx_bounds import validate_tx_string_bounds

PROTOCOL_VERSION = 2
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_HANDSHAKE_MESSAGE_BYTES = 4 * 1024
INBOUND_PEER_TIMEOUT = 5.0
INBOUND_MESSAGE_DEADLINE = 30.0
OUTBOUND_MESSAGE_DEADLINE = 30.0
MAX_INBOUND_PEERS = 32
MAX_INBOUND_PEERS_PER_HOST = 4
# A per-frame 16 MiB cap still permits 32 workers to retain roughly
# 512 MiB of attacker-selected wire payload concurrently, before decoded
# JSON object overhead.  Bound post-handshake in-flight frame bytes across
# the whole listener.  This is transport resource policy only.
MAX_INBOUND_INFLIGHT_FRAME_BYTES = 64 * 1024 * 1024
# Public inbound block validation can otherwise drive full state-root work at
# attacker-selected rates.  These are local ingress budgets, not consensus.
INBOUND_BLOCK_WORK_GLOBAL_RATE = 2.0
INBOUND_BLOCK_WORK_GLOBAL_BURST = 16
INBOUND_BLOCK_WORK_PER_HOST_RATE = 1.0
INBOUND_BLOCK_WORK_PER_HOST_BURST = 8
MAX_INBOUND_BLOCK_WORK_HOSTS = 1024
MAX_SYNC_BLOCKS = 128
MAX_LOCATOR_HASHES = 64
MAX_P2P_TX_INPUTS = 1024
MAX_P2P_TX_OUTPUTS = 1024
# Public standalone TX relay can otherwise trigger unbounded Ed25519/ML-DSA
# verification under the chain+mempool locks.  Work units are local ingress
# policy only: Ed25519=1, ML-DSA=4, hybrid=5.
INBOUND_TX_WORK_ED25519 = 1
INBOUND_TX_WORK_ML_DSA = 4
INBOUND_TX_WORK_HYBRID = 5
INBOUND_TX_WORK_GLOBAL_RATE = 256.0
INBOUND_TX_WORK_GLOBAL_BURST = MAX_P2P_TX_INPUTS * INBOUND_TX_WORK_HYBRID
INBOUND_TX_WORK_PER_HOST_RATE = 64.0
INBOUND_TX_WORK_PER_HOST_BURST = MAX_P2P_TX_INPUTS * INBOUND_TX_WORK_HYBRID
MAX_INBOUND_TX_WORK_HOSTS = 1024
# A valid Ed25519 input needs at least 88 base64 signature chars plus 44
# base64 public-key chars.  Ed25519 is the densest supported scheme per work
# unit, so this derives a conservative fresh-burst upper bound from the
# consensus block byte cap without changing block validity.
MIN_VALID_ED25519_AUTH_TEXT_BYTES = 132
MAX_VALID_BLOCK_SIGNATURE_WORK = (
    int(axven.CHAIN_CONFIG["max_block_bytes"]) // MIN_VALID_ED25519_AUTH_TEXT_BYTES
    + 1
)
INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_RATE = 4096.0
INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK * 4
INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_RATE = 1024.0
INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK
MAX_INBOUND_BLOCK_SIGNATURE_WORK_HOSTS = 1024
# Configured outbound peers are still untrusted network sources.  Give a
# healthy peer one full sync batch of fresh block-validation work, then
# refill above normal chain production without allowing the legacy
# max_rounds reconnect loop to become an unbounded CPU amplifier.
OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_RATE = 8.0
OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_BURST = MAX_SYNC_BLOCKS * 2
OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_RATE = 2.0
OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_BURST = MAX_SYNC_BLOCKS
MAX_OUTBOUND_SYNC_BLOCK_WORK_HOSTS = 1024
# One consensus-max valid signed block must always fit a fresh peer burst;
# repeated expensive blocks are then rate-limited across reconnects.
OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_RATE = 4096.0
OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK * 2
OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_RATE = 1024.0
OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_BURST = MAX_VALID_BLOCK_SIGNATURE_WORK
MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS = 1024
MAX_P2P_MESSAGE_TYPE_CHARS = 32

class ProtocolError(ValueError): pass

class _InboundFrameLease:
    def __init__(self,budget,size):
        self._budget=budget
        self._size=size
        self._released=False

    def release(self):
        if self._released:
            return
        self._released=True
        self._budget._release(self._size)


class _InboundFrameByteBudget:
    """Non-blocking listener-wide reservation for decoded frame lifetime."""
    def __init__(self,max_bytes=MAX_INBOUND_INFLIGHT_FRAME_BYTES):
        if type(max_bytes) is not int or max_bytes < MAX_MESSAGE_BYTES:
            raise ValueError("invalid inbound frame byte budget")
        self._max_bytes=max_bytes
        self._inflight_bytes=0
        self._peak_bytes=0
        self._lock=threading.Lock()

    def reserve(self,size):
        if type(size) is not int or size <= 0 or size > MAX_MESSAGE_BYTES:
            return None
        with self._lock:
            if self._inflight_bytes + size > self._max_bytes:
                return None
            self._inflight_bytes += size
            self._peak_bytes=max(self._peak_bytes,self._inflight_bytes)
        return _InboundFrameLease(self,size)

    def _release(self,size):
        with self._lock:
            self._inflight_bytes -= size
            if self._inflight_bytes < 0:
                raise RuntimeError("inbound frame byte accounting underflow")

    def snapshot(self):
        with self._lock:
            return {
                "max_bytes":self._max_bytes,
                "inflight_bytes":self._inflight_bytes,
                "peak_bytes":self._peak_bytes,
            }


def _work_budget_status(status):
    if not isinstance(status,str):
        return False
    return (
        status == "validation work budget exceeded"
        or status.startswith("Signature work budget exceeded at " )
        or status.startswith("reorg aborted: Signature work budget exceeded at " )
    )

class _InboundBlockWorkLimiter:
    """Thread-safe global + source-host token buckets for expensive blocks."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=INBOUND_BLOCK_WORK_GLOBAL_RATE,
        global_burst=INBOUND_BLOCK_WORK_GLOBAL_BURST,
        per_host_rate=INBOUND_BLOCK_WORK_PER_HOST_RATE,
        per_host_burst=INBOUND_BLOCK_WORK_PER_HOST_BURST,
        max_hosts=MAX_INBOUND_BLOCK_WORK_HOSTS,
    ):
        self._clock=clock
        self._global_rate=float(global_rate)
        self._global_burst=float(global_burst)
        self._per_host_rate=float(per_host_rate)
        self._per_host_burst=float(per_host_burst)
        self._max_hosts=int(max_hosts)
        if (
            self._global_rate <= 0
            or self._global_burst < 1
            or self._per_host_rate <= 0
            or self._per_host_burst < 1
            or self._max_hosts < 1
        ):
            raise ValueError("invalid inbound block work budget")
        now=float(self._clock())
        self._global_tokens=self._global_burst
        self._global_last=now
        self._hosts=OrderedDict()
        self._lock=threading.Lock()

    @staticmethod
    def _refill(tokens, last, now, rate, burst):
        elapsed=max(0.0, now-last)
        return min(burst, tokens + elapsed*rate)

    def consume(self, host):
        if not isinstance(host,str) or not host:
            return False
        now=float(self._clock())
        with self._lock:
            global_tokens=self._refill(
                self._global_tokens, self._global_last, now,
                self._global_rate, self._global_burst,
            )
            entry=self._hosts.get(host)
            if entry is None:
                host_tokens=self._per_host_burst
                host_last=now
            else:
                host_tokens, host_last=entry
                host_tokens=self._refill(
                    host_tokens, host_last, now,
                    self._per_host_rate, self._per_host_burst,
                )

            allowed=(global_tokens >= 1.0 and host_tokens >= 1.0)
            if allowed:
                global_tokens-=1.0
                host_tokens-=1.0

            self._global_tokens=global_tokens
            self._global_last=now
            if entry is None and len(self._hosts) >= self._max_hosts:
                self._hosts.popitem(last=False)
            self._hosts[host]=(host_tokens,now)
            self._hosts.move_to_end(host)
            return allowed

    def snapshot(self):
        with self._lock:
            return {
                "global_tokens": self._global_tokens,
                "hosts": len(self._hosts),
            }


class _InboundTxWorkLimiter:
    """Thread-safe weighted global + source-host TX crypto budget."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=INBOUND_TX_WORK_GLOBAL_RATE,
        global_burst=INBOUND_TX_WORK_GLOBAL_BURST,
        per_host_rate=INBOUND_TX_WORK_PER_HOST_RATE,
        per_host_burst=INBOUND_TX_WORK_PER_HOST_BURST,
        max_hosts=MAX_INBOUND_TX_WORK_HOSTS,
    ):
        self._clock=clock
        self._global_rate=float(global_rate)
        self._global_burst=float(global_burst)
        self._per_host_rate=float(per_host_rate)
        self._per_host_burst=float(per_host_burst)
        self._max_hosts=int(max_hosts)
        if (
            self._global_rate <= 0
            or self._global_burst < 1
            or self._per_host_rate <= 0
            or self._per_host_burst < 1
            or self._max_hosts < 1
        ):
            raise ValueError("invalid inbound transaction work budget")
        now=float(self._clock())
        self._global_tokens=self._global_burst
        self._global_last=now
        self._hosts=OrderedDict()
        self._lock=threading.Lock()

    @staticmethod
    def _refill(tokens, last, now, rate, burst):
        elapsed=max(0.0, now-last)
        return min(burst, tokens + elapsed*rate)

    def consume(self, host, cost):
        if not isinstance(host,str) or not host or type(cost) is not int or cost < 1:
            return False
        now=float(self._clock())
        with self._lock:
            global_tokens=self._refill(
                self._global_tokens, self._global_last, now,
                self._global_rate, self._global_burst,
            )
            entry=self._hosts.get(host)
            if entry is None:
                host_tokens=self._per_host_burst
                host_last=now
            else:
                host_tokens,host_last=entry
                host_tokens=self._refill(
                    host_tokens,host_last,now,
                    self._per_host_rate,self._per_host_burst,
                )
            allowed=(global_tokens >= cost and host_tokens >= cost)
            if allowed:
                global_tokens-=cost
                host_tokens-=cost
            self._global_tokens=global_tokens
            self._global_last=now
            if entry is None and len(self._hosts) >= self._max_hosts:
                self._hosts.popitem(last=False)
            self._hosts[host]=(host_tokens,now)
            self._hosts.move_to_end(host)
            return allowed

    def snapshot(self):
        with self._lock:
            return {
                "global_tokens": self._global_tokens,
                "hosts": len(self._hosts),
            }


class _InboundBlockSignatureWorkLimiter(_InboundTxWorkLimiter):
    """Weighted public block signature budget with a full-block fresh burst."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_RATE,
        global_burst=INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_BURST,
        per_host_rate=INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_RATE,
        per_host_burst=INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST,
        max_hosts=MAX_INBOUND_BLOCK_SIGNATURE_WORK_HOSTS,
    ):
        super().__init__(
            clock=clock,
            global_rate=global_rate,
            global_burst=global_burst,
            per_host_rate=per_host_rate,
            per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


class _OutboundSyncBlockWorkLimiter(_InboundBlockWorkLimiter):
    """Persistent configured-peer block-validation work budget."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_RATE,
        global_burst=OUTBOUND_SYNC_BLOCK_WORK_GLOBAL_BURST,
        per_host_rate=OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_RATE,
        per_host_burst=OUTBOUND_SYNC_BLOCK_WORK_PER_HOST_BURST,
        max_hosts=MAX_OUTBOUND_SYNC_BLOCK_WORK_HOSTS,
    ):
        super().__init__(
            clock=clock, global_rate=global_rate, global_burst=global_burst,
            per_host_rate=per_host_rate, per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


class _OutboundSyncBlockSignatureWorkLimiter(_InboundBlockSignatureWorkLimiter):
    """Persistent configured-peer weighted block-signature budget."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_RATE,
        global_burst=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_BURST,
        per_host_rate=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_RATE,
        per_host_burst=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_BURST,
        max_hosts=MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS,
    ):
        super().__init__(
            clock=clock, global_rate=global_rate, global_burst=global_burst,
            per_host_rate=per_host_rate, per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


def _reject_duplicate_json_keys(pairs):
    obj={}
    for key,value in pairs:
        if key in obj:
            raise ProtocolError(f"duplicate JSON key: {key}")
        obj[key]=value
    return obj

def local_identity() -> Dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "chain_id": axven.CHAIN_ID,
        "config_fingerprint": axven.CONFIG_FINGERPRINT,
        "genesis_hash": axven._genesis().hash(),
    }

_HELLO_FIELDS = {
    "type",
    "protocol_version",
    "chain_id",
    "config_fingerprint",
    "genesis_hash",
}

def validate_handshake(msg: Dict[str, Any]) -> None:
    if any(key not in _HELLO_FIELDS for key in msg):
        raise ProtocolError("unknown hello field")
    expected=local_identity()
    if msg.get("type") != "hello": raise ProtocolError("expected hello")
    if type(msg.get("protocol_version")) is not int:
        raise ProtocolError("protocol_version must be integer")
    for key in ("protocol_version","chain_id","config_fingerprint","genesis_hash"):
        if msg.get(key) != expected[key]:
            raise ProtocolError(f"{key} mismatch")

def _json_bytes(msg) -> bytes:
    return json.dumps(msg,sort_keys=True,separators=(",",":")).encode()

def _validate_message_type(msg: Dict[str, Any]) -> str:
    raw_type=msg.get("type")
    if not isinstance(raw_type,str):
        raise ProtocolError("message type must be string")
    if len(raw_type)>MAX_P2P_MESSAGE_TYPE_CHARS:
        raise ProtocolError("message type too long")
    return raw_type

_BLOCK_TOP_LEVEL_FIELDS = {
    "height",
    "timestamp",
    "previous_hash",
    "merkle_root",
    "target",
    "transactions",
    "nonce",
    "miner",
    "utxo_state_root",
}


def _validate_block_fields(raw_block: Dict[str, Any]) -> None:
    if any(key not in _BLOCK_TOP_LEVEL_FIELDS for key in raw_block):
        raise ProtocolError("unknown block field")


def _validate_block_numeric_fields(raw_block: Dict[str, Any]) -> None:
    for field in ("height","timestamp","target"):
        if type(raw_block.get(field)) is not int:
            raise ProtocolError(f"block {field} must be integer")
    if "nonce" in raw_block and type(raw_block["nonce"]) is not int:
        raise ProtocolError("block nonce must be integer")

def _validate_tx_numeric_fields(raw_tx: Dict[str, Any]) -> None:
    for raw_input in raw_tx.get("inputs",[]):
        if type(raw_input.get("index")) is not int:
            raise ProtocolError("tx input index must be integer")
    for raw_output in raw_tx.get("outputs",[]):
        if type(raw_output.get("amount")) is not int:
            raise ProtocolError("tx output amount must be integer")
    if "coinbase_height" in raw_tx and type(raw_tx["coinbase_height"]) is not int:
        raise ProtocolError("tx coinbase_height must be integer")

_TX_INPUT_OPTIONAL_STRING_FIELDS=(
    "scheme",
    "signature",
    "public_key",
    "ed_signature",
    "ed_public_key",
    "ml_signature",
    "ml_public_key",
)

def _validate_tx_string_fields(raw_tx: Dict[str, Any]) -> None:
    for raw_input in raw_tx.get("inputs",[]):
        if not isinstance(raw_input.get("prev_txid"),str):
            raise ProtocolError("tx input prev_txid must be string")
        for field in _TX_INPUT_OPTIONAL_STRING_FIELDS:
            if field in raw_input and not isinstance(raw_input[field],str):
                raise ProtocolError(f"tx input {field} must be string")
    for raw_output in raw_tx.get("outputs",[]):
        if not isinstance(raw_output.get("recipient"),str):
            raise ProtocolError("tx output recipient must be string")


def _validate_wire_transaction(raw_tx: Dict[str, Any]) -> None:
    """Apply the canonical standalone P2P tx preflight to any wire transaction."""
    if not isinstance(raw_tx, dict):
        raise ProtocolError("tx must be object")
    if "inputs" not in raw_tx:
        raise ProtocolError("tx inputs required")
    if "outputs" not in raw_tx:
        raise ProtocolError("tx outputs required")

    raw_inputs = raw_tx["inputs"]
    raw_outputs = raw_tx["outputs"]
    if not isinstance(raw_inputs, list):
        raise ProtocolError("tx inputs must be list")
    if not isinstance(raw_outputs, list):
        raise ProtocolError("tx outputs must be list")
    if len(raw_inputs) > MAX_P2P_TX_INPUTS:
        raise ProtocolError("too many tx inputs")
    if len(raw_outputs) > MAX_P2P_TX_OUTPUTS:
        raise ProtocolError("too many tx outputs")
    if any(not isinstance(i, dict) for i in raw_inputs):
        raise ProtocolError("tx input entries must be objects")
    if any(not isinstance(o, dict) for o in raw_outputs):
        raise ProtocolError("tx output entries must be objects")

    _validate_tx_numeric_fields(raw_tx)
    _validate_tx_string_fields(raw_tx)
    try:
        validate_tx_string_bounds(raw_tx)
    except ValueError as exc:
        raise ProtocolError(str(exc)) from exc


def send_message(sock: socket.socket, msg: Dict[str, Any]) -> None:
    raw=_json_bytes(msg)
    if len(raw)>MAX_MESSAGE_BYTES: raise ProtocolError("message too large")
    sock.sendall(struct.pack(">I",len(raw))+raw)

def _recv_exact(sock,n,deadline=None):
    out=bytearray()
    while len(out)<n:
        if deadline is not None:
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise ProtocolError("message receive deadline exceeded")
            current_timeout=sock.gettimeout()
            if current_timeout is None:
                sock.settimeout(remaining)
            else:
                sock.settimeout(min(current_timeout,remaining))
        try:
            chunk=sock.recv(n-len(out))
        except socket.timeout as exc:
            if deadline is not None:
                raise ProtocolError("message receive deadline exceeded") from exc
            raise
        if not chunk: raise EOFError("peer closed")
        out.extend(chunk)
    return bytes(out)

def _recv_message_with_lease(
    sock: socket.socket, deadline=None, max_bytes=None, frame_byte_budget=None,
):
    frame_limit=MAX_MESSAGE_BYTES if max_bytes is None else max_bytes
    if type(frame_limit) is not int or frame_limit <= 0:
        raise ProtocolError("invalid message byte limit")
    n=struct.unpack(">I",_recv_exact(sock,4,deadline))[0]
    if n<=0 or n>frame_limit:
        raise ProtocolError("invalid message length")

    lease=None
    if frame_byte_budget is not None:
        lease=frame_byte_budget.reserve(n)
        if lease is None:
            raise ProtocolError("inbound frame byte budget exceeded")

    try:
        raw=_recv_exact(sock,n,deadline)
        try:
            msg=json.loads(raw,object_pairs_hook=_reject_duplicate_json_keys)
        except ProtocolError:
            raise
        except Exception as e:
            raise ProtocolError("invalid json") from e
        if not isinstance(msg,dict):
            raise ProtocolError("message must be object")
        return msg,lease
    except Exception:
        if lease is not None:
            lease.release()
        raise


def recv_message(sock: socket.socket,deadline=None,max_bytes=None) -> Dict[str, Any]:
    msg,lease=_recv_message_with_lease(
        sock,deadline=deadline,max_bytes=max_bytes,frame_byte_budget=None,
    )
    if lease is not None:
        lease.release()
    return msg

def hello_message():
    return {"type":"hello",**local_identity()}

def handshake(sock: socket.socket,deadline=None) -> Dict[str, Any]:
    send_message(sock,hello_message())
    peer=recv_message(
        sock,
        deadline=deadline,
        max_bytes=MAX_HANDSHAKE_MESSAGE_BYTES,
    )
    validate_handshake(peer)
    return peer

class PeerSession:
    def __init__(self, chain: axven.Blockchain, mempool: Optional[axven.Mempool]=None):
        self.chain=chain
        self.mempool=mempool

    def status(self):
        with self.chain._state_lock:
            tip=self.chain.tip
            return {
                "type":"status",
                "height":tip.height,
                "tip_hash":tip.hash(),
                "chainwork":self.chain.chainwork,
            }

    def locator(self):
        with self.chain._state_lock:
            # Simple checkpoint locator; sufficient for rebuilt devnet.
            hs=[]; step=1; i=len(self.chain.blocks)-1
            while i>=0:
                hs.append(self.chain.blocks[i].hash())
                if len(hs)>10: step*=2
                i-=step
            if self.chain.blocks[0].hash() not in hs:
                hs.append(self.chain.blocks[0].hash())
            return hs

    def handle(
        self, msg, block_work_gate=None, tx_work_gate=None,
        block_signature_work_gate=None, stop_on_work_budget=False,
    ):
        typ=_validate_message_type(msg)
        if typ=="status":
            expected_fields={"type","height","tip_hash","chainwork"}
            if set(msg) != expected_fields:
                raise ProtocolError("invalid status message fields")
            raw_height=msg.get("height")
            if type(raw_height) is not int or raw_height < 0:
                raise ProtocolError("invalid status height")
            raw_tip_hash=msg.get("tip_hash")
            if (
                not isinstance(raw_tip_hash,str)
                or len(raw_tip_hash) != 64
                or any(c not in "0123456789abcdef" for c in raw_tip_hash)
            ):
                raise ProtocolError("invalid status tip hash")
            raw_chainwork=msg.get("chainwork")
            if type(raw_chainwork) is not int or raw_chainwork < 0:
                raise ProtocolError("invalid status chainwork")
            return None
        if typ=="get_status":
            if any(key != "type" for key in msg):
                raise ProtocolError("unknown get_status message field")
            return self.status()
        if typ=="tx":
            if any(key not in ("type","tx") for key in msg):
                raise ProtocolError("unknown tx message field")
            if self.mempool is None: raise ProtocolError("mempool unavailable")
            raw_tx=msg.get("tx")
            _validate_wire_transaction(raw_tx)
            tx=axven.Transaction.from_dict(raw_tx)
            if tx_work_gate is None:
                tid=self.mempool.add(tx)
            else:
                tid=self.mempool.add(tx,work_gate=tx_work_gate)
            return {"type":"accepted","kind":"tx","id":tid}
        if typ=="block":
            if any(key not in ("type","block") for key in msg):
                raise ProtocolError("unknown block message field")
            raw_block=msg.get("block")
            if not isinstance(raw_block,dict):
                raise ProtocolError("block must be object")
            _validate_block_fields(raw_block)
            raw_transactions=raw_block.get("transactions")
            if not isinstance(raw_transactions,list):
                raise ProtocolError("block transactions must be list")
            if len(raw_transactions)>axven.MAX_BLOCK_TXS:
                raise ProtocolError("too many block transactions")
            for raw_tx in raw_transactions:
                _validate_wire_transaction(raw_tx)
            _validate_block_numeric_fields(raw_block)
            raw_previous_hash=raw_block.get("previous_hash")
            if not isinstance(raw_previous_hash,str):
                raise ProtocolError("block previous_hash must be string")
            if len(raw_previous_hash)>64:
                raise ProtocolError("block previous_hash too long")
            raw_merkle_root=raw_block.get("merkle_root")
            if not isinstance(raw_merkle_root,str):
                raise ProtocolError("block merkle_root must be string")
            if len(raw_merkle_root)>64:
                raise ProtocolError("block merkle_root too long")
            raw_utxo_state_root=raw_block.get("utxo_state_root")
            if not isinstance(raw_utxo_state_root,str):
                raise ProtocolError("block utxo_state_root must be string")
            if len(raw_utxo_state_root)>64:
                raise ProtocolError("block utxo_state_root too long")
            raw_miner=raw_block.get("miner")
            if raw_block.get("height")==0:
                if raw_miner!=axven.GENESIS_MINER:
                    raise ProtocolError("invalid genesis miner")
            elif not axven.canonical_miner_address_valid(raw_miner):
                raise ProtocolError("block miner invalid")
            block=axven.Block.from_dict(raw_block)
            if block_work_gate is None and block_signature_work_gate is None:
                ok,status=self.chain.add_block(block)
            else:
                kwargs={}
                if block_work_gate is not None:
                    kwargs["work_gate"]=block_work_gate
                if block_signature_work_gate is not None:
                    kwargs["signature_work_gate"]=block_signature_work_gate
                ok,status=self.chain.add_block(block,**kwargs)
            if not ok and status not in ("duplicate","orphan"):
                raise ProtocolError(f"block rejected: {status}")
            return {"type":"accepted","kind":"block","id":block.hash(),"status":status}
        if typ=="get_blocks":
            if any(key not in ("type","locator","limit") for key in msg):
                raise ProtocolError("unknown get_blocks message field")
            raw_locator=msg.get("locator",[])
            if not isinstance(raw_locator,list):
                raise ProtocolError("locator must be list")
            if len(raw_locator)>MAX_LOCATOR_HASHES:
                raise ProtocolError("locator too large")
            if any(not isinstance(h,str) for h in raw_locator):
                raise ProtocolError("locator entries must be strings")
            if any(len(h)>64 for h in raw_locator):
                raise ProtocolError("locator entry too long")
            locator=list(raw_locator)

            raw_limit=msg.get("limit",MAX_SYNC_BLOCKS)
            if type(raw_limit) is not int:
                raise ProtocolError("invalid block limit")
            limit=raw_limit
            if limit<1 or limit>MAX_SYNC_BLOCKS:
                raise ProtocolError("invalid block limit")

            with self.chain._state_lock:
                start=0
                for h in locator:
                    node=self.chain.index.get(h)
                    if node is None:
                        continue
                    height=node.height
                    if (
                        0 <= height < len(self.chain.blocks)
                        and self.chain.blocks[height].hash() == h
                    ):
                        start=height+1
                        break
                blocks=list(
                    self.chain.blocks[
                        start:start+limit
                    ]
                )

            raw_blocks=[]
            reply_size=len(_json_bytes({"type":"blocks","blocks":[]}))
            for block in blocks:
                raw_block=block.to_dict()
                raw_block_size=len(_json_bytes(raw_block))
                candidate_size=(
                    reply_size
                    + raw_block_size
                    + (1 if raw_blocks else 0)
                )
                if candidate_size>MAX_MESSAGE_BYTES:
                    break
                raw_blocks.append(raw_block)
                reply_size=candidate_size

            return {
                "type":"blocks",
                "blocks":raw_blocks,
            }
        if typ=="blocks":
            if any(key not in ("type","blocks") for key in msg):
                raise ProtocolError("unknown blocks message field")
            raw_blocks=msg.get("blocks")
            if not isinstance(raw_blocks,list):
                raise ProtocolError("blocks must be list")
            if len(raw_blocks)>MAX_SYNC_BLOCKS:
                raise ProtocolError("too many blocks")
            accepted=0
            for raw in raw_blocks:
                if not isinstance(raw,dict):
                    raise ProtocolError("block batch entries must be objects")
                _validate_block_fields(raw)
                raw_transactions=raw.get("transactions")
                if not isinstance(raw_transactions,list):
                    raise ProtocolError("block transactions must be list")
                if len(raw_transactions)>axven.MAX_BLOCK_TXS:
                    raise ProtocolError("too many block transactions")
                for raw_tx in raw_transactions:
                    _validate_wire_transaction(raw_tx)
                _validate_block_numeric_fields(raw)
                raw_previous_hash=raw.get("previous_hash")
                if not isinstance(raw_previous_hash,str):
                    raise ProtocolError("block previous_hash must be string")
                if len(raw_previous_hash)>64:
                    raise ProtocolError("block previous_hash too long")
                raw_merkle_root=raw.get("merkle_root")
                if not isinstance(raw_merkle_root,str):
                    raise ProtocolError("block merkle_root must be string")
                if len(raw_merkle_root)>64:
                    raise ProtocolError("block merkle_root too long")
                raw_utxo_state_root=raw.get("utxo_state_root")
                if not isinstance(raw_utxo_state_root,str):
                    raise ProtocolError("block utxo_state_root must be string")
                if len(raw_utxo_state_root)>64:
                    raise ProtocolError("block utxo_state_root too long")
                raw_miner=raw.get("miner")
                if raw.get("height")==0:
                    if raw_miner!=axven.GENESIS_MINER:
                        raise ProtocolError("invalid genesis miner")
                elif not axven.canonical_miner_address_valid(raw_miner):
                    raise ProtocolError("block miner invalid")
                b=axven.Block.from_dict(raw)
                if block_work_gate is None and block_signature_work_gate is None:
                    ok,status=self.chain.add_block(b)
                else:
                    kwargs={}
                    if block_work_gate is not None:
                        kwargs["work_gate"]=block_work_gate
                    if block_signature_work_gate is not None:
                        kwargs["signature_work_gate"]=block_signature_work_gate
                    ok,status=self.chain.add_block(b,**kwargs)
                if ok or status=="duplicate": accepted+=1
                elif status=="orphan": continue
                elif stop_on_work_budget and _work_budget_status(status):
                    return {
                        "type":"accepted", "kind":"blocks",
                        "count":accepted, "work_budget_exhausted":True,
                    }
                else: raise ProtocolError(f"sync block rejected: {status}")
            return {"type":"accepted","kind":"blocks","count":accepted}
        raise ProtocolError("unknown message type")

def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None, frame_byte_budget=None,
):
    try:
        handshake(sock,deadline=time.monotonic()+INBOUND_PEER_TIMEOUT)
        sock.settimeout(INBOUND_PEER_TIMEOUT)
        while True:
            lease=None
            try:
                if frame_byte_budget is None:
                    msg=recv_message(
                        sock,
                        deadline=time.monotonic()+INBOUND_MESSAGE_DEADLINE,
                    )
                else:
                    msg,lease=_recv_message_with_lease(
                        sock,
                        deadline=time.monotonic()+INBOUND_MESSAGE_DEADLINE,
                        frame_byte_budget=frame_byte_budget,
                    )
                sock.settimeout(INBOUND_PEER_TIMEOUT)
                if tx_work_gate is not None or block_signature_work_gate is not None:
                    reply=session.handle(
                        msg,
                        block_work_gate=block_work_gate,
                        tx_work_gate=tx_work_gate,
                        block_signature_work_gate=block_signature_work_gate,
                    )
                elif block_work_gate is not None:
                    reply=session.handle(msg,block_work_gate=block_work_gate)
                else:
                    reply=session.handle(msg)
                if reply is not None:
                    send_message(sock,reply)
            finally:
                if lease is not None:
                    lease.release()
    except (EOFError,OSError,ProtocolError,KeyError,TypeError,ValueError):
        return
    finally:
        try:sock.close()
        except OSError:pass

def sync_once(sock,session:PeerSession,limit=128):
    msg=request(
        sock,
        {"type":"get_blocks","locator":session.locator(),"limit":limit},
    )
    if msg.get("type")!="blocks": raise ProtocolError("expected blocks")
    return session.handle(msg)


class NodeServer:
    """Small threaded TCP node wrapper for integration/devnet operation."""
    def __init__(self, chain=None, mempool=None, host="127.0.0.1", port=0):
        self.chain=chain or axven.Blockchain()
        self.mempool=mempool or axven.Mempool(self.chain)
        self.session=PeerSession(self.chain,self.mempool)
        self.host=host; self.port=port
        self._sock=None; self._thread=None; self._stop=threading.Event()
        self._clients=set(); self._client_hosts={}; self._lock=threading.Lock()
        self._block_work_limiter=_InboundBlockWorkLimiter()
        self._tx_work_limiter=_InboundTxWorkLimiter()
        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()
        self._frame_byte_budget=_InboundFrameByteBudget()

    @property
    def address(self):
        if self._sock is None:return (self.host,self.port)
        return self._sock.getsockname()

    def start(self):
        if self._sock is not None:return self
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind((self.host,self.port)); sock.listen(16); sock.settimeout(.2)
        self._sock=sock
        def loop():
            while not self._stop.is_set():
                try: c,remote=sock.accept()
                except socket.timeout: continue
                except OSError: break
                c.settimeout(INBOUND_PEER_TIMEOUT)
                remote_host=remote[0]
                with self._lock:
                    host_count=sum(
                        1 for host in self._client_hosts.values()
                        if host == remote_host
                    )
                    if (
                        len(self._clients) >= MAX_INBOUND_PEERS
                        or host_count >= MAX_INBOUND_PEERS_PER_HOST
                    ):
                        reject = True
                    else:
                        self._clients.add(c)
                        self._client_hosts[c]=remote_host
                        reject = False
                if reject:
                    try:
                        c.close()
                    except OSError:
                        pass
                    continue
                def worker(client=c,source_host=remote_host):
                    block_gate=lambda: self._block_work_limiter.consume(source_host)
                    tx_gate=lambda cost: self._tx_work_limiter.consume(
                        source_host,cost
                    )
                    block_signature_gate=lambda cost: (
                        self._block_signature_work_limiter.consume(source_host,cost)
                    )
                    try:
                        serve_connection(
                            client,self.session,
                            block_work_gate=block_gate,
                            tx_work_gate=tx_gate,
                            block_signature_work_gate=block_signature_gate,
                            frame_byte_budget=self._frame_byte_budget,
                        )
                    finally:
                        with self._lock:
                            self._clients.discard(client)
                            self._client_hosts.pop(client,None)
                threading.Thread(target=worker,daemon=True).start()
        self._thread=threading.Thread(target=loop,daemon=True); self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._sock:
            try:self._sock.close()
            except OSError:pass
        with self._lock:
            for c in list(self._clients):
                try:c.close()
                except OSError:pass
        if self._thread:self._thread.join(1)
        self._sock=None

def connect(address,timeout=3.0):
    s=socket.create_connection(address,timeout=timeout)
    s.settimeout(timeout)
    deadline=(None if timeout is None else time.monotonic()+timeout)
    try:
        handshake(s,deadline=deadline)
    except Exception:
        try:s.close()
        except OSError:pass
        raise
    s.settimeout(timeout)
    return s

def request(sock,msg,deadline=None):
    send_message(sock,msg)
    if deadline is None:
        deadline=time.monotonic()+OUTBOUND_MESSAGE_DEADLINE
    original_timeout=sock.gettimeout()
    try:
        return recv_message(sock,deadline=deadline)
    finally:
        try:sock.settimeout(original_timeout)
        except OSError:pass

def sync_to_peer(
    address, session, limit=128, max_rounds=100,
    block_work_gate=None, block_signature_work_gate=None,
):
    """Reconnect-friendly catch-up until empty reply or local work budget."""
    total=0
    sock=connect(address)
    try:
        for _ in range(max_rounds):
            reply=request(sock,{"type":"get_blocks","locator":session.locator(),"limit":limit})
            if reply.get("type")!="blocks":raise ProtocolError("expected blocks")
            blocks=reply.get("blocks")
            if not isinstance(blocks,list):raise ProtocolError("blocks must be list")
            if not blocks:break
            if block_work_gate is None and block_signature_work_gate is None:
                result=session.handle(reply)
            else:
                result=session.handle(
                    reply,
                    block_work_gate=block_work_gate,
                    block_signature_work_gate=block_signature_work_gate,
                    stop_on_work_budget=True,
                )
            total+=result["count"]
            if result.get("work_budget_exhausted"):
                break
        return total
    finally:
        try:sock.close()
        except OSError:pass

_BLOCK_ACK_STATUSES = {
    "extended",
    "reorg",
    "side-chain",
    "duplicate",
    "orphan",
}

def _validate_propagation_ack(reply,kind,expected_id):
    if kind == "tx":
        expected_fields={"type","kind","id"}
    elif kind == "block":
        expected_fields={"type","kind","id","status"}
    else:
        raise ValueError("unsupported propagation kind")
    if set(reply) != expected_fields:
        raise ProtocolError("invalid propagation acknowledgement fields")
    if reply.get("type") != "accepted":
        raise ProtocolError("expected propagation acknowledgement")
    if reply.get("kind") != kind:
        raise ProtocolError("propagation acknowledgement kind mismatch")
    if reply.get("id") != expected_id:
        raise ProtocolError("propagation acknowledgement id mismatch")
    if kind == "block" and reply.get("status") not in _BLOCK_ACK_STATUSES:
        raise ProtocolError("invalid block acknowledgement status")
    return reply

def propagate_tx(address,tx):
    sock=connect(address)
    try:
        reply=request(sock,{"type":"tx","tx":tx.to_dict()})
        return _validate_propagation_ack(reply,"tx",tx.txid())
    finally:sock.close()

def propagate_block(address,block):
    sock=connect(address)
    try:
        reply=request(sock,{"type":"block","block":block.to_dict()})
        return _validate_propagation_ack(reply,"block",block.hash())
    finally:sock.close()
