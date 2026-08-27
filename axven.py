#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, json
import threading
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
CHAIN_CONFIG={"chain_id":"axven-devnet-2","smt_activation_height":10000,"pq_hybrid_activation_height":2000,"pq_pure_activation_height":5000,"pq_scheme":"ml-dsa-44","max_block_bytes":7*1024*1024}
CHAIN_ID=CHAIN_CONFIG["chain_id"]
_CONFIG_CANONICAL=json.dumps(CHAIN_CONFIG,sort_keys=True,separators=(",",":")).encode()
CONFIG_FINGERPRINT=sha256(b"axven-config-v1|"+_CONFIG_CANONICAL)
GENESIS_MINER=f"{CHAIN_ID}-genesis:{CONFIG_FINGERPRINT}"
SCHEME_ED25519="ed25519"; SCHEME_ML_DSA="ml-dsa-44"; SCHEME_HYBRID="hybrid-ed25519+ml-dsa-44"
NULL_TXID="0"*64; COINBASE_INDEX=0xffffffff

def _b64e(b): return base64.b64encode(b).decode("ascii")
def _b64d(s): return base64.b64decode(s.encode("ascii"),validate=True)
def address_from_pubkey(pub): return "N"+sha256(pub)[:40]
def ml_address_from_pubkey(pub): return "M"+sha256(pub)[:40]
def hybrid_address(ed_pub,ml_pub): return "H"+sha256(ed_pub+ml_pub)[:40]
def scheme_of_address(addr):
    if not isinstance(addr,str) or not addr: raise ValueError("Invalid address")
    return {"N":SCHEME_ED25519,"M":SCHEME_ML_DSA,"H":SCHEME_HYBRID}.get(addr[0]) or (_ for _ in ()).throw(ValueError("Unknown address scheme"))
def output_scheme_allowed(recipient,height):
    try: scheme=scheme_of_address(recipient)
    except ValueError: return False
    h1=CHAIN_CONFIG["pq_hybrid_activation_height"]; h2=CHAIN_CONFIG["pq_pure_activation_height"]
    if height<h1: return scheme==SCHEME_ED25519
    if height<h2: return scheme in (SCHEME_ML_DSA,SCHEME_HYBRID)
    return scheme==SCHEME_ML_DSA

def canonical_miner_address_valid(addr):
    return (
        isinstance(addr,str)
        and len(addr)==41
        and addr[0] in ("N","M","H")
        and all(c in "0123456789abcdef" for c in addr[1:])
    )

@dataclass
class TxInput:
    prev_txid:str; index:int; signature:str=""; public_key:str=""; scheme:str=""; ed_signature:str=""; ed_public_key:str=""; ml_signature:str=""; ml_public_key:str=""; wire_extra:Optional[Dict[str,Any]]=None
@dataclass
class TxOutput:
    amount:int; recipient:str

def _input_get(inp,name,default=None): return inp.get(name,default) if isinstance(inp,dict) else getattr(inp,name,default)
_ALLOWED={SCHEME_ED25519:{"prev_txid","index","signature","public_key"},SCHEME_ML_DSA:{"prev_txid","index","scheme","signature","public_key"},SCHEME_HYBRID:{"prev_txid","index","scheme","ed_signature","ed_public_key","ml_signature","ml_public_key"}}
def canonical_input_valid(inp):
    scheme=_input_get(inp,"scheme","") or SCHEME_ED25519; allowed=_ALLOWED.get(scheme)
    if not allowed or _input_get(inp,"wire_extra",None): return False
    if isinstance(inp,dict):
        for k,v in inp.items():
            if k not in allowed and k!="wire_extra" and v not in ("",None,{},[]): return False
    else:
        for k in ("signature","public_key","scheme","ed_signature","ed_public_key","ml_signature","ml_public_key"):
            if k not in allowed and getattr(inp,k,"") not in ("",None): return False
    req={SCHEME_ED25519:("prev_txid","signature","public_key"),SCHEME_ML_DSA:("prev_txid","scheme","signature","public_key"),SCHEME_HYBRID:("prev_txid","scheme","ed_signature","ed_public_key","ml_signature","ml_public_key")}[scheme]
    return all(_input_get(inp,k,None) not in (None,"") for k in req)
def canonical_input(inp):
    s=_input_get(inp,"scheme","") or SCHEME_ED25519
    if s==SCHEME_ED25519: keys=("prev_txid","index","signature","public_key")
    elif s==SCHEME_ML_DSA: keys=("prev_txid","index","scheme","signature","public_key")
    elif s==SCHEME_HYBRID: keys=("prev_txid","index","scheme","ed_signature","ed_public_key","ml_signature","ml_public_key")
    else: raise ValueError("Unknown input scheme")
    return {k:(s if k=="scheme" else _input_get(inp,k,"")) for k in keys}
def _to_txinput(obj):
    if isinstance(obj,TxInput): return obj
    if not isinstance(obj,dict): raise TypeError("input must be TxInput or dict")
    known=set(TxInput.__dataclass_fields__)-{"wire_extra"}; extras={k:v for k,v in obj.items() if k not in known}; data={k:v for k,v in obj.items() if k in known}; ti=TxInput(**data); ti.wire_extra=extras or None; return ti
class Transaction:
    def __init__(self,inputs,outputs,coinbase_height=None): self.inputs=list(inputs); self.outputs=[o if isinstance(o,TxOutput) else TxOutput(**o) for o in outputs]; self.coinbase_height=coinbase_height
    def _in(self): return [_to_txinput(i) for i in self.inputs]
    def commitment(self):
        d={"chain_id":CHAIN_ID,"inputs":[{"prev_txid":i.prev_txid,"index":i.index} for i in self._in()],"outputs":[asdict(o) for o in self.outputs]}
        if self.coinbase_height is not None: d["coinbase_height"]=self.coinbase_height
        return d
    def txid(self): return sha256(json.dumps(self.commitment(),sort_keys=True,separators=(",",":")).encode())
    def sighash(self): return bytes.fromhex(self.txid())
    def to_dict(self):
        d={"inputs":[canonical_input(i) for i in self._in()],"outputs":[asdict(o) for o in self.outputs]}
        if self.coinbase_height is not None: d["coinbase_height"]=self.coinbase_height
        return d
    @classmethod
    def from_dict(cls,d): return cls([_to_txinput(i) for i in d.get("inputs",[])],[TxOutput(**o) for o in d.get("outputs",[])],d.get("coinbase_height"))
class Wallet:
    def __init__(self,private_key=None): self.private_key=private_key or Ed25519PrivateKey.generate(); self.public_key=self.private_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); self.address=address_from_pubkey(self.public_key)
    def sign(self,sh): return self.private_key.sign(sh)
    def sign_input(self,tx,i):
        inp=tx._in()[i]; return {"prev_txid":inp.prev_txid,"index":inp.index,"signature":_b64e(self.sign(tx.sighash())),"public_key":_b64e(self.public_key)}
_ML=None
def _mldsa():
    global _ML
    if _ML is not None:return _ML
    try: from dilithium_py.ml_dsa import ML_DSA_44
    except Exception:
        from dilithium_py.ml_dsa.default_parameters import ML_DSA_44
    _ML=ML_DSA_44; return _ML
class MLDSAWallet:
    def __init__(self,keypair=None):
        if keypair is None:self.public_key,self._secret=_mldsa().keygen()
        else:self.public_key,self._secret=keypair
        self.address=ml_address_from_pubkey(self.public_key)
    def sign(self,sh): return _mldsa().sign(self._secret,sh)
    def sign_input(self,tx,i):
        inp=tx._in()[i]; return {"prev_txid":inp.prev_txid,"index":inp.index,"scheme":SCHEME_ML_DSA,"signature":_b64e(self.sign(tx.sighash())),"public_key":_b64e(self.public_key)}
class HybridWallet:
    def __init__(self,ed_wallet=None,ml_wallet=None): self.ed_wallet=ed_wallet or Wallet(); self.ml_wallet=ml_wallet or MLDSAWallet(); self.ed_public_key=self.ed_wallet.public_key; self.ml_public_key=self.ml_wallet.public_key; self.address=hybrid_address(self.ed_public_key,self.ml_public_key)
    def sign_input(self,tx,i):
        inp=tx._in()[i]; sh=tx.sighash(); return {"prev_txid":inp.prev_txid,"index":inp.index,"scheme":SCHEME_HYBRID,"ed_signature":_b64e(self.ed_wallet.sign(sh)),"ed_public_key":_b64e(self.ed_public_key),"ml_signature":_b64e(self.ml_wallet.sign(sh)),"ml_public_key":_b64e(self.ml_public_key)}
def verify_input(inp,utxo,sighash,height=0):
    try:
        if not canonical_input_valid(inp): return False
        req=scheme_of_address(utxo["recipient"]); scheme=_input_get(inp,"scheme","") or SCHEME_ED25519
        if scheme!=req:return False
        if req==SCHEME_ED25519:
            pub=_b64d(_input_get(inp,"public_key")); sig=_b64d(_input_get(inp,"signature"));
            if address_from_pubkey(pub)!=utxo["recipient"]: return False
            Ed25519PublicKey.from_public_bytes(pub).verify(sig,sighash); return True
        if req==SCHEME_ML_DSA:
            pub=_b64d(_input_get(inp,"public_key")); sig=_b64d(_input_get(inp,"signature"));
            return ml_address_from_pubkey(pub)==utxo["recipient"] and bool(_mldsa().verify(pub,sighash,sig))
        if req==SCHEME_HYBRID:
            ep=_b64d(_input_get(inp,"ed_public_key")); es=_b64d(_input_get(inp,"ed_signature")); mp=_b64d(_input_get(inp,"ml_public_key")); ms=_b64d(_input_get(inp,"ml_signature"));
            if hybrid_address(ep,mp)!=utxo["recipient"]: return False
            Ed25519PublicKey.from_public_bytes(ep).verify(es,sighash); return bool(_mldsa().verify(mp,sighash,ms))
        return False
    except Exception:return False
def outpoint(txid,index): return f"{txid}:{index}"


# ---------------------------------------------------------------------------
# Rebuild checkpoint 2: consensus restoration
# PoW + chainwork + contextual headers + transactional reorg + state roots.
# ---------------------------------------------------------------------------
import copy
import os
import time
from pathlib import Path

# Monetary / consensus parameters retained from the pre-loss Axven/NOVA lineage.
DECIMALS = 8
COIN = 10 ** DECIMALS
MAX_SUPPLY = 21_000_000 * COIN
INITIAL_REWARD = 50 * COIN
HALVING_INTERVAL = 210_000

POW_LIMIT_BITS = 248
MAX_TARGET = (1 << POW_LIMIT_BITS) - 1
TARGET_BLOCK_TIME = 2
ADJUST_INTERVAL = 2016
TARGET_TIMESPAN = ADJUST_INTERVAL * TARGET_BLOCK_TIME
RETARGET_CLAMP = 4
MEDIAN_TIME_SPAN = 11
GENESIS_TIME = 0

COINBASE_MATURITY = 100
DUST = 1
MAX_BLOCK_TXS = 1_000
MAX_ORPHAN_BLOCKS = 256
MAX_ORPHAN_BYTES = 64 * 1024 * 1024
MAX_MEMPOOL_TXS = 4096
MAX_MEMPOOL_BYTES = 64 * 1024 * 1024

EMPTY_ROOT = sha256(b"")
SMT_DEPTH = 256
SMT_EMPTY_LEAF = "00" * 32


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def block_reward(height: int, issued: int) -> int:
    if height <= 0:
        return 0
    halvings = (height - 1) // HALVING_INTERVAL
    reward = INITIAL_REWARD >> halvings if halvings < 64 else 0
    return max(0, min(reward, MAX_SUPPLY - issued))


def work_of(target: int) -> int:
    return (1 << 256) // (target + 1)


def compute_next_target(prev_target: int, actual_timespan: int) -> int:
    lo = TARGET_TIMESPAN // RETARGET_CLAMP
    hi = TARGET_TIMESPAN * RETARGET_CLAMP
    span = max(lo, min(hi, actual_timespan))
    return max(1, min(MAX_TARGET, prev_target * span // TARGET_TIMESPAN))


def next_target_for_height(blocks, height: int) -> int:
    if height <= 1:
        return MAX_TARGET
    prev = blocks[height - 1]
    if height % ADJUST_INTERVAL != 0:
        return prev.target
    first = blocks[height - ADJUST_INTERVAL]
    last = blocks[height - 1]
    return compute_next_target(prev.target, last.timestamp - first.timestamp)


def median_time_past(blocks, height: int) -> int:
    lo = max(0, height - MEDIAN_TIME_SPAN)
    times = sorted(b.timestamp for b in blocks[lo:height])
    return times[len(times) // 2]


def merkle_root(hashes) -> str:
    if not hashes:
        return EMPTY_ROOT
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) & 1:
            layer.append(layer[-1])
        layer = [sha256(bytes.fromhex(layer[i]) + bytes.fromhex(layer[i + 1]))
                 for i in range(0, len(layer), 2)]
    return layer[0]


def _utxo_leaf(op: str, u: Dict[str, Any]) -> str:
    raw = f"{op}|{u['amount']}|{u['recipient']}|{int(u['coinbase'])}|{u['height']}"
    return sha256(raw.encode())


def utxo_root(utxo: Dict[str, Dict[str, Any]]) -> str:
    if not utxo:
        return EMPTY_ROOT
    return merkle_root([_utxo_leaf(op, utxo[op]) for op in sorted(utxo)])


def smt_key(op: str) -> str:
    return sha256(b"axven-smt-key-v1|" + op.encode())


def smt_value(op: str, u: Dict[str, Any]) -> str:
    raw = f"axven-smt-leaf-v1|{op}|{u['amount']}|{u['recipient']}|{int(u['coinbase'])}|{u['height']}"
    return sha256(raw.encode())


def _smt_defaults():
    d = [None] * (SMT_DEPTH + 1)
    d[SMT_DEPTH] = SMT_EMPTY_LEAF
    for depth in range(SMT_DEPTH - 1, -1, -1):
        child = bytes.fromhex(d[depth + 1])
        d[depth] = sha256(child + child)
    return d


SMT_DEFAULTS = _smt_defaults()
SMT_EMPTY_ROOT = SMT_DEFAULTS[0]


def smt_root_reference(utxo: Dict[str, Dict[str, Any]]) -> str:
    """Canonical full Sparse-Merkle recompute. Correctness/reference path."""
    if not utxo:
        return SMT_EMPTY_ROOT
    nodes = {}
    for op, u in utxo.items():
        key = int(smt_key(op), 16)
        nodes[key] = smt_value(op, u)
    # At each step key is the prefix index of the current node.
    for depth in range(SMT_DEPTH, 0, -1):
        parents = {}
        touched = {k >> 1 for k in nodes}
        default = SMT_DEFAULTS[depth]
        for p in touched:
            left = nodes.get(p << 1, default)
            right = nodes.get((p << 1) | 1, default)
            h = sha256(bytes.fromhex(left) + bytes.fromhex(right))
            if h != SMT_DEFAULTS[depth - 1]:
                parents[p] = h
        nodes = parents
    return nodes.get(0, SMT_EMPTY_ROOT)



class SparseMerkleTree:
    """Incremental sparse Merkle mirror.

    This is deliberately a *parallel state primitive*.  The consensus
    reference function ``smt_root_reference`` remains untouched and is used
    as the oracle in tests.  Only non-default nodes are stored.
    """
    def __init__(self, utxo: Optional[Dict[str, Dict[str, Any]]] = None):
        self.nodes: Dict[Tuple[int, int], str] = {}
        self.values: Dict[str, Dict[str, Any]] = {}
        if utxo:
            self.rebuild(utxo)

    @property
    def root(self) -> str:
        return self.nodes.get((0, 0), SMT_EMPTY_ROOT)

    def _set_node(self, depth: int, prefix: int, value: str):
        key = (depth, prefix)
        if value == SMT_DEFAULTS[depth]:
            self.nodes.pop(key, None)
        else:
            self.nodes[key] = value

    def _leaf_hash(self, op: str, u: Optional[Dict[str, Any]]) -> str:
        return SMT_EMPTY_LEAF if u is None else smt_value(op, u)

    def update(self, op: str, u: Optional[Dict[str, Any]]):
        """Insert/update ``op`` or delete it when ``u`` is None."""
        key_int = int(smt_key(op), 16)
        if u is None:
            self.values.pop(op, None)
        else:
            self.values[op] = dict(u)

        leaf = self._leaf_hash(op, u)
        self._set_node(SMT_DEPTH, key_int, leaf)

        child_prefix = key_int
        for depth in range(SMT_DEPTH, 0, -1):
            parent = child_prefix >> 1
            left_prefix = parent << 1
            right_prefix = left_prefix | 1
            left = self.nodes.get((depth, left_prefix), SMT_DEFAULTS[depth])
            right = self.nodes.get((depth, right_prefix), SMT_DEFAULTS[depth])
            ph = sha256(bytes.fromhex(left) + bytes.fromhex(right))
            self._set_node(depth - 1, parent, ph)
            child_prefix = parent
        return self.root

    def apply_changes(self, deletes: Iterable[str] = (),
                      puts: Optional[Dict[str, Dict[str, Any]]] = None):
        for op in deletes:
            self.update(op, None)
        for op, u in (puts or {}).items():
            self.update(op, u)
        return self.root

    def rebuild(self, utxo: Dict[str, Dict[str, Any]]):
        self.nodes.clear()
        self.values = {}
        for op in sorted(utxo):
            self.update(op, utxo[op])
        return self.root

    def prove(self, op: str) -> Dict[str, Any]:
        """Return a 256-sibling inclusion/non-inclusion proof."""
        key_int = int(smt_key(op), 16)
        siblings = []
        prefix = key_int
        for depth in range(SMT_DEPTH, 0, -1):
            sibling_prefix = prefix ^ 1
            siblings.append(self.nodes.get((depth, sibling_prefix),
                                           SMT_DEFAULTS[depth]))
            prefix >>= 1
        return {
            "op": op,
            "value": dict(self.values[op]) if op in self.values else None,
            "siblings": siblings,
            "root": self.root,
        }


def smt_verify_proof(op: str, value: Optional[Dict[str, Any]],
                     siblings: Iterable[str], root: str) -> bool:
    siblings = list(siblings)
    if len(siblings) != SMT_DEPTH:
        return False
    key_int = int(smt_key(op), 16)
    h = SMT_EMPTY_LEAF if value is None else smt_value(op, value)
    prefix = key_int
    for sibling in siblings:
        try:
            sb = bytes.fromhex(sibling)
            hb = bytes.fromhex(h)
        except (TypeError, ValueError):
            return False
        h = sha256(hb + sb) if (prefix & 1) == 0 else sha256(sb + hb)
        prefix >>= 1
    return h == root

def state_root_scheme(height: int) -> str:
    return "legacy" if height < CHAIN_CONFIG["smt_activation_height"] else "sparse"


def expected_state_root(utxo: Dict[str, Dict[str, Any]], height: int) -> str:
    return utxo_root(utxo) if state_root_scheme(height) == "legacy" else smt_root_reference(utxo)


def serialized_transaction_size(tx: "Transaction") -> int:
    return len(
        json.dumps(
            tx.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def serialized_block_size(block: "Block") -> int:
    # Matches the P2P JSON payload shape used by the rebuilt network layer.
    return len(json.dumps({"block": block.to_dict()}, separators=(",", ":")).encode())


def block_size_valid(block: "Block") -> bool:
    return serialized_block_size(block) <= int(CHAIN_CONFIG["max_block_bytes"])


@property
def _tx_is_coinbase(self):
    ins = self._in()
    return (len(ins) == 1 and ins[0].prev_txid == NULL_TXID
            and ins[0].index == COINBASE_INDEX)
Transaction.is_coinbase = _tx_is_coinbase


def make_coinbase(recipient: str, amount: int, height: int) -> Transaction:
    return Transaction([TxInput(NULL_TXID, COINBASE_INDEX)],
                       [TxOutput(amount, recipient)], coinbase_height=height)


@dataclass
class Block:
    height: int
    timestamp: int
    previous_hash: str
    merkle_root: str
    target: int
    transactions: List[Dict[str, Any]]
    nonce: int = 0
    miner: str = ""
    utxo_state_root: str = ""

    @property
    def prev_hash(self):
        return self.previous_hash

    def header(self):
        return {
            "height": self.height,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "target": self.target,
            "utxo_state_root": self.utxo_state_root,
            "nonce": self.nonce,
            "miner": self.miner,
        }

    def hash(self):
        return sha256(canonical(self.header()))

    def pow_ok(self):
        return int(self.hash(), 16) <= self.target

    def txs(self):
        return [Transaction.from_dict(t) for t in self.transactions]

    def to_dict(self):
        return {
            "height": self.height,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "target": self.target,
            "transactions": self.transactions,
            "nonce": self.nonce,
            "miner": self.miner,
            "utxo_state_root": self.utxo_state_root,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            int(d["height"]), int(d["timestamp"]), d["previous_hash"],
            d["merkle_root"], int(d["target"]), list(d["transactions"]),
            int(d.get("nonce", 0)), d.get("miner", ""), d.get("utxo_state_root", ""),
        )


def _genesis() -> Block:
    return Block(
        height=0, timestamp=GENESIS_TIME, previous_hash="0" * 64,
        merkle_root=merkle_root([]), target=MAX_TARGET, transactions=[], nonce=0,
        miner=GENESIS_MINER, utxo_state_root=EMPTY_ROOT,
    )


@dataclass
class BlockNode:
    block: Block
    height: int
    chainwork: int
    parent_hash: str


@dataclass
class BlockUndo:
    spent: list
    created: list
    reward: int


def _check_context(block: Block, path: List[Block], height: int):
    if block.height != height: return f"Bad height at {height}"
    if block.previous_hash != path[-1].hash(): return f"Broken link at {height}"
    if block.target != next_target_for_height(path, height): return f"Wrong target at {height}"
    if not (1 <= block.target <= MAX_TARGET): return f"Target out of range at {height}"
    if not block.pow_ok(): return f"PoW fail at {height}"
    if block.timestamp <= median_time_past(path, height): return f"Timestamp <= MTP at {height}"
    if not block.transactions: return f"No coinbase at {height}"
    if len(block.transactions) > MAX_BLOCK_TXS: return f"Block too many txs at {height}"
    if not block_size_valid(block): return f"Block exceeds max bytes at {height}"
    try:
        txs = block.txs()
    except Exception:
        return f"Malformed transaction at {height}"
    if block.merkle_root != merkle_root([t.txid() for t in txs]): return f"Merkle mismatch at {height}"
    if not txs[0].is_coinbase: return f"First tx not coinbase at {height}"
    if any(t.is_coinbase for t in txs[1:]): return f"Extra coinbase at {height}"
    if txs[0].coinbase_height != height: return f"Coinbase height wrong at {height}"
    if not canonical_miner_address_valid(block.miner): return f"Invalid miner at {height}"
    if len(txs[0].outputs)==1 and block.miner != txs[0].outputs[0].recipient:
        return f"Miner/coinbase mismatch at {height}"
    return None


def _transition(block: Block, utxo: Dict[str, Dict[str, Any]], height: int, issued: int):
    """Apply transactions in place WITHOUT checking the header state-root."""
    txs = block.txs()
    coinbase = txs[0]
    spent, created, created_set, total_fees = [], [], set(), 0

    def rollback():
        for op in created:
            utxo.pop(op, None)
        for op, u in reversed(spent):
            if op not in created_set:
                utxo[op] = u

    for tx in txs[1:]:
        sh = tx.sighash()
        seen = set()
        in_sum = 0
        # Validate all inputs first against the current live state.
        for i in tx._in():
            op = outpoint(i.prev_txid, i.index)
            if op in seen:
                rollback(); return False, f"Duplicate input at {height}", None, 0, 0
            seen.add(op)
            u = utxo.get(op)
            if u is None:
                rollback(); return False, f"Missing/spent input at {height}", None, 0, 0
            if u["coinbase"] and height - u["height"] < COINBASE_MATURITY:
                rollback(); return False, f"Immature coinbase spend at {height}", None, 0, 0
            if not verify_input(i, u, sh, height):
                rollback(); return False, f"Bad signature at {height}", None, 0, 0
            in_sum += int(u["amount"])
        out_sum = 0
        for o in tx.outputs:
            if o.amount < DUST:
                rollback(); return False, f"Dust output at {height}", None, 0, 0
            if not output_scheme_allowed(o.recipient, height):
                rollback(); return False, f"Forbidden output scheme at {height}", None, 0, 0
            out_sum += int(o.amount)
        if out_sum > in_sum:
            rollback(); return False, f"Overspend at {height}", None, 0, 0
        total_fees += in_sum - out_sum
        for i in tx._in():
            op = outpoint(i.prev_txid, i.index)
            u = utxo.pop(op)
            spent.append((op, u))
        tid = tx.txid()
        for idx, o in enumerate(tx.outputs):
            op = outpoint(tid, idx)
            utxo[op] = {"amount": o.amount, "recipient": o.recipient,
                        "coinbase": False, "height": height}
            created.append(op); created_set.add(op)

    reward = block_reward(height, issued)
    if len(coinbase.outputs) != 1:
        rollback(); return False, f"Bad coinbase outputs at {height}", None, 0, 0
    cbout = coinbase.outputs[0]
    if not output_scheme_allowed(cbout.recipient, height):
        rollback(); return False, f"Forbidden coinbase output scheme at {height}", None, 0, 0
    if cbout.amount != reward + total_fees:
        rollback(); return False, f"Bad coinbase amount at {height}", None, 0, 0
    cbid = coinbase.txid()
    op = outpoint(cbid, 0)
    utxo[op] = {"amount": cbout.amount, "recipient": cbout.recipient,
                "coinbase": True, "height": height}
    created.append(op); created_set.add(op)
    return True, "OK", BlockUndo(spent, created, reward), reward, total_fees


def _undo_forward(undo: BlockUndo, utxo):
    created_set = set(undo.created)
    for op in undo.created:
        utxo.pop(op, None)
    for op, u in reversed(undo.spent):
        if op not in created_set:
            utxo[op] = u


def _apply_forward(block, utxo, height, issued):
    ok, reason, undo, reward, fees = _transition(block, utxo, height, issued)
    if not ok:
        return False, reason, None, 0, 0
    got = expected_state_root(utxo, height)
    if got != block.utxo_state_root:
        _undo_forward(undo, utxo)
        return False, f"Bad state root at {height}", None, 0, 0
    return True, "OK", undo, reward, fees


class Blockchain:
    def __init__(self):
        self.blocks = []
        self.utxo = {}
        self.total_issued = 0
        self.chainwork = 0
        self.index = {}
        self.undo = {}
        self.orphans = {}
        self.orphan_sizes = {}
        self.orphan_bytes = 0
        self.mempool = None
        self._state_lock = threading.RLock()
        self._init_genesis()

    def _init_genesis(self):
        g = _genesis()
        self.blocks = [g]
        gw = work_of(g.target)
        self.chainwork = gw
        self.index[g.hash()] = BlockNode(g, 0, gw, "0" * 64)

    @property
    def tip(self):
        return self.blocks[-1]

    def _ancestry(self, h):
        out = []
        while h in self.index:
            node = self.index[h]
            out.append(node.block)
            if node.height == 0:
                break
            h = node.parent_hash
        out.reverse()
        return out

    def balance(self, address):
        with self._state_lock:
            return sum(
                u["amount"]
                for u in self.utxo.values()
                if u["recipient"] == address
            )

    def spendable(self, address):
        with self._state_lock:
            out = []
            tip_height = self.tip.height
            for op, u in self.utxo.items():
                if u["recipient"] != address:
                    continue
                if u["coinbase"] and tip_height - u["height"] < COINBASE_MATURITY:
                    continue
                txid, idx = op.rsplit(":", 1)
                out.append((txid, int(idx), int(u["amount"])))
            return out

    def build_candidate(self, miner_address, mempool=None):
        with self._state_lock:
            return self._build_candidate_locked(miner_address, mempool)

    def _build_candidate_locked(self, miner_address, mempool=None):
        height = self.tip.height + 1
        if not output_scheme_allowed(miner_address, height):
            raise ValueError(f"Forbidden coinbase output scheme at {height}")
        selected = mempool.select() if mempool else []
        total_fees = 0
        for tx in selected:
            in_sum = sum(self.utxo[outpoint(i.prev_txid, i.index)]["amount"] for i in tx._in())
            total_fees += in_sum - sum(o.amount for o in tx.outputs)
        reward = block_reward(height, self.total_issued)
        coinbase = make_coinbase(miner_address, reward + total_fees, height)
        ordered = [coinbase] + selected
        block = Block(
            height=height,
            timestamp=max(int(time.time()), median_time_past(self.blocks, height) + 1),
            previous_hash=self.tip.hash(),
            merkle_root=merkle_root([t.txid() for t in ordered]),
            target=next_target_for_height(self.blocks, height),
            transactions=[t.to_dict() for t in ordered],
            nonce=0,
            miner=miner_address,
            utxo_state_root="",
        )
        trial = copy.deepcopy(self.utxo)
        ok, reason, _undo, _reward, _fees = _transition(block, trial, height, self.total_issued)
        if not ok:
            raise ValueError(reason)
        block.utxo_state_root = expected_state_root(trial, height)
        while not block.pow_ok():
            block.nonce += 1
        return block

    def mine(self, miner_address, mempool=None):
        block = self.build_candidate(miner_address, mempool)
        ok, status = self.add_block(block)
        if not ok:
            raise RuntimeError(f"Self-mined block rejected: {status}")
        return block

    def add_block(self, block):
        with self._state_lock:
            return self._add_block_locked(block)

    def _add_block_locked(self, block):
        h = block.hash()
        if h in self.index:
            return False, "duplicate"
        parent = block.previous_hash
        if parent not in self.index:
            block_bytes = serialized_block_size(block)
            if block_bytes > int(CHAIN_CONFIG["max_block_bytes"]):
                return False, "orphan exceeds max bytes"
            bucket = self.orphans.get(parent, [])
            if any(child.hash() == h for child in bucket):
                return False, "duplicate orphan"
            orphan_count = sum(len(v) for v in self.orphans.values())
            if orphan_count >= MAX_ORPHAN_BLOCKS:
                return False, "orphan pool full"
            if self.orphan_bytes + block_bytes > MAX_ORPHAN_BYTES:
                return False, "orphan byte budget full"
            self.orphans.setdefault(parent, []).append(block)
            self.orphan_sizes[h] = block_bytes
            self.orphan_bytes += block_bytes
            return False, "orphan"
        parent_node = self.index[parent]
        height = parent_node.height + 1
        path = self._ancestry(parent)
        err = _check_context(block, path, height)
        if err:
            return False, err
        cw = parent_node.chainwork + work_of(block.target)
        node = BlockNode(block, height, cw, parent)
        self.index[h] = node

        if parent == self.tip.hash():
            ok, reason, undo, reward, _fees = _apply_forward(
                block, self.utxo, height, self.total_issued)
            if not ok:
                del self.index[h]
                return False, reason
            self.blocks.append(block)
            self.undo[h] = undo
            self.total_issued += reward
            self.chainwork = cw
            if self.mempool:
                self.mempool.remove_confirmed(block.txs()[1:])
            status = "extended"
        elif cw > self.chainwork:
            ok, reason = self._reorg_to(node)
            if not ok:
                del self.index[h]
                return False, f"reorg aborted: {reason}"
            status = "reorg"
        else:
            status = "side-chain"
        self._connect_orphans(h)
        return True, status

    def _reorg_to(self, node):
        tu = copy.deepcopy(self.utxo)
        tblocks = list(self.blocks)
        tissued, tcw = self.total_issued, self.chainwork
        tundo = dict(self.undo)
        active_hashes = {b.hash() for b in self.blocks}
        branch = []
        cur = node
        while cur.block.hash() not in active_hashes:
            branch.append(cur)
            cur = self.index[cur.parent_hash]
        fork_hash = cur.block.hash()
        branch.reverse()
        disconnected = []
        while tblocks[-1].hash() != fork_hash:
            blk = tblocks[-1]
            undo = tundo.pop(blk.hash())
            _undo_forward(undo, tu)
            tissued -= undo.reward
            tcw -= work_of(blk.target)
            tblocks.pop()
            disconnected.append(blk)
        for bn in branch:
            blk = bn.block
            hh = len(tblocks)
            ok, reason, undo, reward, _fees = _apply_forward(blk, tu, hh, tissued)
            if not ok:
                return False, reason
            tblocks.append(blk)
            tundo[blk.hash()] = undo
            tissued += reward
            tcw += work_of(blk.target)
        self.utxo, self.blocks = tu, tblocks
        self.total_issued, self.chainwork, self.undo = tissued, tcw, tundo
        self._reevaluate_mempool(disconnected)
        return True, "OK"

    def _reevaluate_mempool(self, disconnected=None):
        if self.mempool is None:
            return
        candidates = list(self.mempool.txs.values())
        for blk in disconnected or []:
            candidates.extend(blk.txs()[1:])
        self.mempool.txs.clear(); self.mempool.fees.clear(); self.mempool.spent.clear(); self.mempool.tx_sizes.clear(); self.mempool.total_bytes = 0
        for tx in candidates:
            try:
                self.mempool.add(tx)
            except ValueError:
                pass

    def _connect_orphans(self, h):
        queue = [h]
        while queue:
            parent = queue.pop()
            for child in self.orphans.pop(parent, []):
                child_hash = child.hash()
                child_bytes = self.orphan_sizes.pop(child_hash, 0)
                self.orphan_bytes = max(0, self.orphan_bytes - child_bytes)
                ok, _ = self.add_block(child)
                if ok:
                    queue.append(child_hash)

    def validate_reason(self):
        utxo, issued = {}, 0
        if not self.blocks or self.blocks[0].hash() != _genesis().hash():
            return False, "Bad genesis identity"
        if self.blocks[0].utxo_state_root != EMPTY_ROOT:
            return False, "Bad genesis state root"
        for h, block in enumerate(self.blocks[1:], start=1):
            err = _check_context(block, self.blocks[:h], h)
            if err:
                return False, err
            ok, reason, _undo, reward, _fees = _apply_forward(block, utxo, h, issued)
            if not ok:
                return False, reason
            issued += reward
        if issued > MAX_SUPPLY:
            return False, "Max supply exceeded"
        if utxo != self.utxo:
            return False, "UTXO mismatch"
        return True, "OK"

    def validate(self):
        return self.validate_reason()[0]


class Mempool:
    def __init__(self, chain: Blockchain):
        self.chain = chain
        self.txs, self.fees, self.spent = {}, {}, set()
        self.tx_sizes = {}
        self.total_bytes = 0
        chain.mempool = self

    def add(self, tx: Transaction) -> str:
        if tx.is_coinbase:
            raise ValueError("Coinbase cannot enter the mempool")
        tid = tx.txid()
        if tid in self.txs:
            raise ValueError("Already in mempool")
        if len(self.txs) >= MAX_MEMPOOL_TXS:
            raise ValueError("Mempool full")
        tx_bytes = serialized_transaction_size(tx)
        if self.total_bytes + tx_bytes > MAX_MEMPOOL_BYTES:
            raise ValueError("Mempool byte budget full")
        ops = [outpoint(i.prev_txid, i.index) for i in tx._in()]
        if len(ops) != len(set(ops)) or any(op in self.spent for op in ops):
            raise ValueError("Double spend")
        in_sum = 0
        sh = tx.sighash()
        for i, op in zip(tx._in(), ops):
            u = self.chain.utxo.get(op)
            if u is None:
                raise ValueError("Input not found / unconfirmed")
            if u["coinbase"] and self.chain.tip.height - u["height"] < COINBASE_MATURITY:
                raise ValueError("Coinbase not mature")
            if not verify_input(i, u, sh, self.chain.tip.height + 1):
                raise ValueError("Bad signature")
            in_sum += u["amount"]
        out_sum = 0
        for o in tx.outputs:
            if o.amount < DUST:
                raise ValueError("Dust / non-positive output")
            if not output_scheme_allowed(o.recipient, self.chain.tip.height + 1):
                raise ValueError("Forbidden output scheme")
            out_sum += o.amount
        if out_sum > in_sum:
            raise ValueError("Outputs exceed inputs")
        self.txs[tid] = tx
        self.fees[tid] = in_sum - out_sum
        self.tx_sizes[tid] = tx_bytes
        self.total_bytes += tx_bytes
        self.spent.update(ops)
        return tid

    def select(self, limit=MAX_BLOCK_TXS - 1):
        chosen, used = [], set()
        for tid in sorted(self.txs, key=lambda t: self.fees[t], reverse=True):
            tx = self.txs[tid]
            ops = {outpoint(i.prev_txid, i.index) for i in tx._in()}
            if ops & used:
                continue
            chosen.append(tx); used |= ops
            if len(chosen) >= limit:
                break
        return chosen

    def remove_confirmed(self, txs):
        for tx in txs:
            self.remove(tx.txid())

    def remove(self, txid):
        tx = self.txs.pop(txid, None)
        self.fees.pop(txid, None)
        tx_bytes = self.tx_sizes.pop(txid, 0)
        if tx is not None:
            self.total_bytes = max(0, self.total_bytes - tx_bytes)
            for i in tx._in():
                self.spent.discard(outpoint(i.prev_txid, i.index))


class StateStore:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "chain.json"

    def persist(self, chain: Blockchain):
        payload = {
            "chain_id": CHAIN_ID,
            "config_fingerprint": CONFIG_FINGERPRINT,
            "blocks": [b.to_dict() for b in chain.blocks],
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        os.replace(tmp, self.path)

    def load(self) -> Blockchain:
        payload = json.loads(self.path.read_text())
        if payload.get("chain_id") != CHAIN_ID:
            raise ValueError("chain_id mismatch")
        if payload.get("config_fingerprint") != CONFIG_FINGERPRINT:
            raise ValueError("config fingerprint mismatch")
        blocks = [Block.from_dict(b) for b in payload.get("blocks", [])]
        if not blocks or blocks[0].hash() != _genesis().hash():
            raise ValueError("Bad genesis identity")
        bc = Blockchain()
        for blk in blocks[1:]:
            ok, reason = bc.add_block(blk)
            if not ok:
                raise ValueError(f"load failed: {reason}")
        bc.mempool = None  # v1 ground truth: mempool is deliberately in-memory only.
        return bc


def _selftest_consensus_restoration():
    """Fast Ed25519-only invariant test; no external PQ dependency required."""
    w = Wallet()
    bc = Blockchain(); mp = Mempool(bc)
    # Mine maturity plus spend room.
    for _ in range(COINBASE_MATURITY + 2):
        bc.mine(w.address)
    assert bc.validate()
    assert bc.tip.utxo_state_root == expected_state_root(bc.utxo, bc.tip.height)
    # Build one spend by hand and sign through canonical witness path.
    txid, idx, amount = sorted(bc.spendable(w.address), key=lambda c: c[2], reverse=True)[0]
    tx = Transaction([TxInput(txid, idx)], [TxOutput(amount - 1000, w.address)])
    signed = Transaction([w.sign_input(tx, 0)], tx.outputs)
    mp.add(signed)
    bc.mine(w.address, mp)
    assert signed.txid() not in mp.txs
    assert bc.validate()
    # Tampered state-root must be rejected on a fresh candidate.
    bad = bc.build_candidate(w.address)
    bad.utxo_state_root = "00" * 32
    # Re-mine because root participates in PoW header.
    bad.nonce = 0
    while not bad.pow_ok(): bad.nonce += 1
    ok, reason = bc.add_block(bad)
    assert not ok and "state root" in reason.lower()
    return True
