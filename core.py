#!/usr/bin/env python3
"""Axven Core service layer — checkpoint 6.

Unifies chain, mempool, wallet orchestration, mining and P2P helpers without
changing consensus.  RPC is layered on top in rpc.py.
"""
from __future__ import annotations
from contextlib import nullcontext
from typing import Optional, Tuple
import math
import threading
from datetime import datetime, timezone

import axven
import p2p
import wallet


def _mempool_guard(mempool):
    lock=getattr(mempool,"_lock",None)
    return lock if lock is not None else nullcontext()

def _peer_guard(core):
    lock=getattr(core,"_peer_lock",None)
    return lock if lock is not None else nullcontext()

def _peer_locked(method):
    def wrapped(self,*args,**kwargs):
        with _peer_guard(self):
            return method(self,*args,**kwargs)
    return wrapped


class AxvenCore:
    # Configured outbound peers drive retry/health metadata and persisted
    # configuration. Bound operator-controlled cardinality so local RPC or
    # a corrupt config cannot grow those structures without limit.
    MAX_CONFIGURED_PEERS = 256
    PEER_HEALTH_INCIDENT_HISTORY_LIMIT = 64
    PEER_HEALTH_HISTORY_LIMIT = 64

    def __init__(self, chain: Optional[axven.Blockchain] = None,
                 mempool: Optional[axven.Mempool] = None,
                 identity: Optional[wallet.WalletIdentity] = None):
        self.chain = chain or axven.Blockchain()
        self.mempool = mempool or axven.Mempool(self.chain)
        self.identity = identity
        self.pending = wallet.PendingTracker()
        self.p2p_server = None
        self._peer_lock = threading.RLock()
        # Persist automatic configured-peer work budgets on the core, not
        # on a socket.  Reconnecting therefore cannot mint a fresh burst.
        self._outbound_sync_block_work_limiter = (
            p2p._OutboundSyncBlockWorkLimiter()
        )
        self._outbound_sync_block_signature_work_limiter = (
            p2p._OutboundSyncBlockSignatureWorkLimiter()
        )
        self.outbound_peers = []
        self.peer_last_error = {}
        self.peer_sync_successes = {}
        self.peer_consecutive_failures = {}
        self.peer_last_success_at = {}
        self.peer_last_failure_at = {}
        self.peer_retry_delay_seconds = {}
        self.peer_next_retry_at = {}
        self.peer_retry_base_interval = {}
        self.peer_health_current_state = {}
        self.peer_previous_health_state = {}
        self.peer_health_transition_count = {}
        self.peer_last_health_transition_at = {}
        self.peer_health_transition_history = {}
        self.peer_health_incident_active = {}
        self.peer_health_incident_started_at = {}
        self.peer_health_incident_count = {}
        self.peer_last_health_incident = {}
        self.peer_health_incident_opening_state = {}
        self.peer_health_incident_unhealthy_transitions = {}
        self.peer_health_incident_last_unhealthy_state = {}
        self.peer_health_incident_history_entries = {}
        self.peer_persist_callback = None
        self.shutdown_requested = False
        # SEC-136: active-chain confirmed transaction lookup cache.
        # This is service-layer state only; consensus/persistence remain unchanged.
        self._confirmed_tx_index = {}
        self._confirmed_tx_index_height = -1
        self._confirmed_tx_index_tip_hash = None

    def require_wallet(self):
        if self.identity is None:
            raise RuntimeError("wallet not loaded")
        return self.identity

    def status(self):
        # Height, tip hash and chainwork form one logical chain snapshot.
        # Serialize this read with active-chain mutation/reorg publication.
        with self.chain._state_lock:
            with _mempool_guard(self.mempool):
                tip = self.chain.tip
                return {
                    "chain_id": axven.CHAIN_ID,
                    "config_fingerprint": axven.CONFIG_FINGERPRINT,
                    "genesis_hash": axven._genesis().hash(),
                    "height": tip.height,
                    "tip_hash": tip.hash(),
                    "chainwork": self.chain.chainwork,
                    "mempool_size": len(self.mempool.txs),
                    "wallet_loaded": self.identity is not None,
                }

    def overview(self):
        data = self.status()
        if self.identity is not None:
            data["addresses"] = self.addresses()
            data["balances"] = self.balance()
        else:
            data["addresses"] = None
            data["balances"] = None
        return data

    def recent_blocks(self, limit=20):
        with self.chain._state_lock:
            limit=max(1,min(int(limit),200))
            out=[]
            for b in reversed(self.chain.blocks[-limit:]):
                out.append({
                    "height": b.height,
                    "hash": b.hash(),
                    "previous_hash": b.previous_hash,
                    "timestamp": b.timestamp,
                    "tx_count": len(b.transactions),
                    "miner": b.miner,
                    "target": b.target,
                    "utxo_state_root": b.utxo_state_root,
                })
            return out

    @staticmethod
    def _validate_block_id(block_id):
        # Public block lookup accepts only the legacy built-in int/string
        # domain. Reject coercion aliases and oversized strings before they
        # can acquire the chain-state lock or touch the block index.
        if type(block_id) is int:
            return block_id
        if type(block_id) is not str:
            raise ValueError("invalid block id")
        if len(block_id) > 64:
            raise ValueError("block id too long")
        return block_id

    def get_block(self, block_id):
        block_id=self._validate_block_id(block_id)
        with self.chain._state_lock:
            return self._get_block_locked(block_id)

    def _get_block_locked(self, block_id):
        block_id=self._validate_block_id(block_id)
        block=None
        if isinstance(block_id,int) or (isinstance(block_id,str) and block_id.isdigit()):
            h=int(block_id)
            if 0 <= h < len(self.chain.blocks):
                block=self.chain.blocks[h]
        else:
            node=self.chain.index.get(str(block_id))
            if node is not None:
                block=node.block
        if block is None:
            raise KeyError("block not found")
        txs=block.txs()
        return {
            "height": block.height,
            "hash": block.hash(),
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "merkle_root": block.merkle_root,
            "target": block.target,
            "nonce": block.nonce,
            "miner": block.miner,
            "utxo_state_root": block.utxo_state_root,
            "transactions": [
                {"txid": tx.txid(), "coinbase": bool(tx.is_coinbase), "tx": tx.to_dict()}
                for tx in txs
            ],
        }

    @staticmethod
    def _validate_transaction_id(txid):
        # Transaction ids are SHA-256 hexdigests. Reject aliases and malformed
        # values before they can acquire the chain state lock or touch caches.
        if not isinstance(txid,str):
            raise ValueError("invalid transaction id")
        if len(txid) > 64:
            raise ValueError("transaction id too long")
        if len(txid) != 64 or any(ch not in "0123456789abcdef" for ch in txid):
            raise ValueError("invalid transaction id")
        return txid

    def get_transaction(self, txid):
        txid=self._validate_transaction_id(txid)
        with self.chain._state_lock:
            return self._get_transaction_locked(txid)

    def _refresh_confirmed_tx_index_locked(self):
        """Return an exact active-chain tx index while holding chain state lock."""
        blocks=self.chain.blocks
        if not blocks:
            self._confirmed_tx_index={}
            self._confirmed_tx_index_height=-1
            self._confirmed_tx_index_tip_hash=None
            return self._confirmed_tx_index

        index=getattr(self,"_confirmed_tx_index",None)
        cached_height=getattr(self,"_confirmed_tx_index_height",-1)
        cached_tip=getattr(self,"_confirmed_tx_index_tip_hash",None)
        current_height=len(blocks)-1
        current_tip=blocks[-1].hash()

        if (
            index is not None
            and cached_height == current_height
            and cached_tip == current_tip
        ):
            return index

        # Normal extension can update only the newly active suffix.  Any
        # rollback/reorg invalidates the cached active tip and rebuilds from
        # the current chain, automatically dropping disconnected txids.
        if (
            index is not None
            and 0 <= cached_height < len(blocks)
            and cached_tip == blocks[cached_height].hash()
        ):
            start=cached_height+1
        else:
            index={}
            start=0

        for block_pos in range(start,len(blocks)):
            block=blocks[block_pos]
            for tx_pos,raw_tx in enumerate(block.transactions):
                tx=axven.Transaction.from_dict(raw_tx)
                # Forward iteration with overwrite preserves the legacy
                # reverse-search result if a duplicate txid ever exists.
                index[tx.txid()]=(block_pos,tx_pos)

        self._confirmed_tx_index=index
        self._confirmed_tx_index_height=current_height
        self._confirmed_tx_index_tip_hash=current_tip
        return index

    def _get_transaction_locked(self, txid):
        txid=self._validate_transaction_id(txid)
        with _mempool_guard(self.mempool):
            if txid in self.mempool.txs:
                tx=self.mempool.txs[txid]
                return {"txid":txid,"status":"mempool","tx":tx.to_dict()}

        confirmed=self._refresh_confirmed_tx_index_locked().get(txid)
        if confirmed is None:
            raise KeyError("transaction not found")
        block_pos,tx_pos=confirmed
        block=self.chain.blocks[block_pos]
        tx=axven.Transaction.from_dict(block.transactions[tx_pos])
        return {
            "txid":txid,
            "status":"confirmed",
            "height":block.height,
            "block_hash":block.hash(),
            "tx":tx.to_dict(),
        }

    def mempool_view(self, limit=100):
        limit=max(1,min(int(limit),500))
        with _mempool_guard(self.mempool):
            out=[]
            for txid,tx in list(self.mempool.txs.items())[:limit]:
                out.append({
                    "txid":txid,
                    "fee":int(self.mempool.fees.get(txid,0)),
                    "inputs":len(tx.inputs),
                    "outputs":len(tx.outputs),
                })
            return {"size":len(self.mempool.txs),"transactions":out}

    def explorer_summary(self):
        with self.chain._state_lock:
            st=self.status()
            st["latest_blocks"]=self.recent_blocks(10)
            st["mempool"]=self.mempool_view(20)
            # The active tip already commits the canonical post-block UTXO
            # root. Recomputing it for every Explorer request is O(UTXO) and
            # unnecessarily extends the chain-state lock hold time.
            st["state_root"]=self.chain.tip.utxo_state_root
            return st

    def chain_config(self):
        return dict(axven.CHAIN_CONFIG)

    def addresses(self):
        w = self.require_wallet()
        return {"N": w.address_n, "M": w.address_m, "H": w.address_h}

    @staticmethod
    def _validate_scheme_bound(scheme):
        if scheme is not None and len(str(scheme)) > 64:
            raise ValueError("scheme too long")

    def balance(self, scheme=None):
        self._validate_scheme_bound(scheme)
        w = self.require_wallet()
        if scheme is None:
            return {
                axven.SCHEME_ED25519: self.chain.balance(w.address_n),
                axven.SCHEME_ML_DSA: self.chain.balance(w.address_m),
                axven.SCHEME_HYBRID: self.chain.balance(w.address_h),
            }
        return self.chain.balance(w.address_of(scheme))

    def wallet_status(self, scheme=None):
        self._validate_scheme_bound(scheme)
        with self.chain._state_lock:
            return self._wallet_status_locked(scheme)

    def _wallet_status_locked(self, scheme=None):
        w = self.require_wallet()

        def status_for(selected_scheme):
            address = w.address_of(selected_scheme)
            total = int(self.chain.balance(address))
            mature = list(self.chain.spendable(address))

            reserved = sum(
                int(amount)
                for txid, idx, amount in mature
                if self.pending.is_reserved((txid, idx))
            )
            spendable = sum(
                int(amount)
                for txid, idx, amount in mature
                if not self.pending.is_reserved((txid, idx))
            )
            immature = total - spendable - reserved

            return {
                "total": total,
                "spendable": spendable,
                "reserved": reserved,
                "immature": immature,
            }

        if scheme is not None:
            return status_for(scheme)

        return {
            selected_scheme: status_for(selected_scheme)
            for selected_scheme in (
                axven.SCHEME_ED25519,
                axven.SCHEME_ML_DSA,
                axven.SCHEME_HYBRID,
            )
        }

    def list_unspent(self, scheme):
        self._validate_scheme_bound(scheme)
        with self.chain._state_lock:
            w = self.require_wallet()
            return [
                {"txid": txid, "index": idx, "amount": amount}
                for txid, idx, amount in self.chain.spendable(w.address_of(scheme))
                if not self.pending.is_reserved((txid, idx))
            ]

    def mine(self, count=1, scheme=None):
        self._validate_scheme_bound(scheme)
        if count <= 0:
            raise ValueError("count must be positive")
        w = self.require_wallet()
        if scheme is None:
            height = self.chain.tip.height + 1
            # Choose the first wallet address that consensus permits at the next height.
            for candidate in (axven.SCHEME_ED25519, axven.SCHEME_ML_DSA, axven.SCHEME_HYBRID):
                addr = w.address_of(candidate)
                if axven.output_scheme_allowed(addr, height):
                    scheme = candidate
                    break
        address = w.address_of(scheme)
        hashes = []
        for _ in range(count):
            block = self.chain.mine(address, self.mempool)
            hashes.append(block.hash())
            with _mempool_guard(self.mempool):
                self.pending.reconcile(self.mempool)
            self._propagate_block_outbound(block)
        return hashes

    def send(self, input_scheme, recipient, amount, fee):
        self._validate_scheme_bound(input_scheme)
        if len(str(recipient)) > 256:
            raise ValueError("recipient address too long")
        w = self.require_wallet()
        tx = wallet.build_transaction(
            self.chain, w, input_scheme, recipient, int(amount), int(fee),
            height=self.chain.tip.height + 1, tracker=self.pending
        )
        signed = wallet.sign_transaction(w, tx, input_scheme)
        txid = self.mempool.add(signed)
        ops = [axven.outpoint(i.prev_txid, i.index) for i in signed._in()]
        self.pending.reserve(txid, ops)
        self._propagate_tx_outbound(signed)
        return {"txid": txid, "transaction": signed.to_dict()}

    def start_p2p(self, host="127.0.0.1", port=0):
        if self.p2p_server is not None:
            return self.p2p_server.address
        if len(str(host)) > 255:
            raise ValueError("P2P listener host too long")
        self.p2p_server = p2p.NodeServer(
            self.chain, self.mempool, host=host, port=int(port)
        ).start()
        return self.p2p_server.address

    @staticmethod
    def _parse_peer(peer):
        if isinstance(peer,(tuple,list)) and len(peer)==2:
            host=str(peer[0]).strip()
            port=int(peer[1])
        else:
            raw=str(peer).strip()
            if ":" not in raw:
                raise ValueError("peer must be host:port")
            host,port=raw.rsplit(":",1)
            host=host.strip()
            port=int(port)
        if not host:
            raise ValueError("peer host required")
        if len(host) > 255:
            raise ValueError("peer host too long")
        if not 1 <= port <= 65535:
            raise ValueError("invalid peer port")
        return (host,port)

    @staticmethod
    def _peer_health_timestamp():
        return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

    def outbound_peer_addresses(self):
        with _peer_guard(self):
            return list(self.outbound_peers)

    @_peer_locked
    def add_outbound_peer(self, peer):
        addr=self._parse_peer(peer)
        if addr not in self.outbound_peers:
            if len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS:
                raise ValueError("configured peer limit exceeded")
            self.outbound_peers.append(addr)
            self.peer_health_current_state[addr]=self.peer_health_state(addr)
            if self.peer_persist_callback is not None:
                self.peer_persist_callback(list(self.outbound_peers))
        return addr

    @_peer_locked
    def remove_outbound_peer(self, peer):
        addr=self._parse_peer(peer)
        removed=addr in self.outbound_peers
        if removed:
            self.outbound_peers.remove(addr)
            if self.peer_persist_callback is not None:
                self.peer_persist_callback(list(self.outbound_peers))
        self.peer_last_error.pop(addr,None)
        self.peer_sync_successes.pop(addr,None)
        self.peer_consecutive_failures.pop(addr,None)
        self.peer_last_success_at.pop(addr,None)
        self.peer_last_failure_at.pop(addr,None)
        self.peer_health_current_state.pop(addr,None)
        self.peer_previous_health_state.pop(addr,None)
        self.peer_health_transition_count.pop(addr,None)
        self.peer_last_health_transition_at.pop(addr,None)
        self.peer_health_transition_history.pop(addr,None)
        self.peer_health_incident_active.pop(addr,None)
        self.peer_health_incident_started_at.pop(addr,None)
        self.peer_health_incident_count.pop(addr,None)
        self.peer_last_health_incident.pop(addr,None)
        self.peer_health_incident_opening_state.pop(addr,None)
        self.peer_health_incident_unhealthy_transitions.pop(addr,None)
        self.peer_health_incident_last_unhealthy_state.pop(addr,None)
        self.peer_health_incident_history_entries.pop(addr,None)
        self.clear_peer_retry_schedule(addr)
        return {"host":addr[0],"port":addr[1],"removed":removed}

    @_peer_locked
    def peer_health_state(self, peer):
        """Return the operator-facing health classification for one peer."""
        addr=self._parse_peer(peer)
        last_error=self.peer_last_error.get(addr)
        successes=self.peer_sync_successes.get(addr,0)
        last_failure=self.peer_last_failure_at.get(addr)

        retry_delay=self.peer_retry_delay_seconds.get(addr)
        retry_base=self.peer_retry_base_interval.get(addr,0)
        backoff_active=(
            retry_delay is not None
            and retry_delay > retry_base
        )

        if last_error is not None:
            if backoff_active:
                return "backoff"
            return "offline"

        if successes == 0:
            return "never_connected"

        if last_failure is not None:
            return "recovered"

        return "healthy"

    @_peer_locked
    def peer_health_incident_history(self, peer):
        """Return a defensive copy of bounded completed incident history."""
        addr=self._parse_peer(peer)
        return [
            dict(entry)
            for entry in self.peer_health_incident_history_entries.get(addr,[])
        ]

    @_peer_locked
    def peer_health_history(self, peer):
        """Return a defensive copy of bounded health transition history."""
        addr=self._parse_peer(peer)
        return [
            dict(entry)
            for entry in self.peer_health_transition_history.get(addr,[])
        ]

    @_peer_locked
    def record_peer_health_transition(self, peer):
        """Record a health-state change for one configured outbound peer."""
        addr=self._parse_peer(peer)
        new_state=self.peer_health_state(addr)
        current_state=self.peer_health_current_state.get(addr)

        # First observation establishes the baseline without counting
        # a transition.
        if current_state is None:
            self.peer_health_current_state[addr]=new_state
            return {
                "changed":False,
                "previous":None,
                "current":new_state,
            }

        if new_state == current_state:
            return {
                "changed":False,
                "previous":self.peer_previous_health_state.get(addr),
                "current":new_state,
            }

        self.peer_previous_health_state[addr]=current_state
        self.peer_health_current_state[addr]=new_state
        self.peer_health_transition_count[addr]=(
            self.peer_health_transition_count.get(addr,0)+1
        )
        self.peer_last_health_transition_at[addr]=(
            self._peer_health_timestamp()
        )

        history=self.peer_health_transition_history.setdefault(addr,[])
        history.append({
            "from_state":current_state,
            "to_state":new_state,
            "at":self.peer_last_health_transition_at[addr],
        })

        overflow=len(history)-self.PEER_HEALTH_HISTORY_LIMIT
        if overflow > 0:
            del history[:overflow]

        unhealthy_states={"offline","backoff"}

        if new_state in unhealthy_states:
            if not self.peer_health_incident_active.get(addr,False):
                self.peer_health_incident_active[addr]=True
                self.peer_health_incident_started_at[addr]=(
                    self.peer_last_health_transition_at[addr]
                )
                self.peer_health_incident_count[addr]=(
                    self.peer_health_incident_count.get(addr,0)+1
                )
                self.peer_health_incident_opening_state[addr]=current_state
                self.peer_health_incident_unhealthy_transitions[addr]=1
            else:
                self.peer_health_incident_unhealthy_transitions[addr]=(
                    self.peer_health_incident_unhealthy_transitions.get(addr,0)+1
                )

            self.peer_health_incident_last_unhealthy_state[addr]=new_state

        elif (
            new_state == "recovered"
            and self.peer_health_incident_active.get(addr,False)
        ):
            self.peer_last_health_incident[addr]={
                "from_state":self.peer_health_incident_opening_state.get(addr),
                "last_unhealthy_state":self.peer_health_incident_last_unhealthy_state.get(addr),
                "recovered_to":new_state,
                "started_at":self.peer_health_incident_started_at.get(addr),
                "ended_at":self.peer_last_health_transition_at[addr],
                "unhealthy_transitions":self.peer_health_incident_unhealthy_transitions.get(addr,0),
            }

            incident_history=self.peer_health_incident_history_entries.setdefault(addr,[])
            incident_history.append(
                dict(self.peer_last_health_incident[addr])
            )

            overflow=(
                len(incident_history)
                - self.PEER_HEALTH_INCIDENT_HISTORY_LIMIT
            )
            if overflow > 0:
                del incident_history[:overflow]

            self.peer_health_incident_active[addr]=False
            self.peer_health_incident_started_at.pop(addr,None)
            self.peer_health_incident_opening_state.pop(addr,None)
            self.peer_health_incident_unhealthy_transitions.pop(addr,None)
            self.peer_health_incident_last_unhealthy_state.pop(addr,None)

        return {
            "changed":True,
            "previous":current_state,
            "current":new_state,
        }

    @_peer_locked
    def outbound_peer_status(self):
        return [
            {
                "host":host,
                "port":port,
                "health_state":self.peer_health_state((host,port)),
                "previous_health_state":self.peer_previous_health_state.get((host,port)),
                "health_transition_count":self.peer_health_transition_count.get((host,port),0),
                "last_health_transition_at":self.peer_last_health_transition_at.get((host,port)),
                "health_history":self.peer_health_history((host,port)),
                "health_incident_active":self.peer_health_incident_active.get((host,port),False),
                "health_incident_started_at":self.peer_health_incident_started_at.get((host,port)),
                "health_incident_count":self.peer_health_incident_count.get((host,port),0),
                "last_health_incident":(
                    dict(self.peer_last_health_incident[(host,port)])
                    if (host,port) in self.peer_last_health_incident
                    else None
                ),
                "health_incident_history":self.peer_health_incident_history((host,port)),
                "last_error":self.peer_last_error.get((host,port)),
                "sync_successes":self.peer_sync_successes.get((host,port),0),
                "consecutive_failures":self.peer_consecutive_failures.get((host,port),0),
                "last_success_at":self.peer_last_success_at.get((host,port)),
                "last_failure_at":self.peer_last_failure_at.get((host,port)),
                "retry_delay_seconds":self.peer_retry_delay_seconds.get((host,port)),
                "next_retry_at":self.peer_next_retry_at.get((host,port)),
                "retry_backoff_active":(
                    self.peer_retry_delay_seconds.get((host,port)) is not None
                    and self.peer_retry_delay_seconds.get((host,port),0)
                        > self.peer_retry_base_interval.get((host,port),0)
                ),
            }
            for host,port in self.outbound_peers
        ]

    @_peer_locked
    def peer_health_summary(self):
        peers=self.outbound_peer_status()
        total=len(peers)
        unhealthy=sum(1 for peer in peers if peer["last_error"] is not None)
        healthy=total-unhealthy
        total_successes=sum(peer["sync_successes"] for peer in peers)
        total_failures=sum(peer["consecutive_failures"] for peer in peers)

        recovered=sum(
            1 for peer in peers
            if peer["last_error"] is None
            and peer["sync_successes"] > 0
            and peer["last_failure_at"] is not None
        )

        backoff_active=sum(
            1 for peer in peers
            if peer["retry_backoff_active"]
        )

        never_connected=sum(
            1 for peer in peers
            if peer["sync_successes"] == 0
        )

        return {
            "total":total,
            "healthy":healthy,
            "unhealthy":unhealthy,
            "total_sync_successes":total_successes,
            "total_consecutive_failures":total_failures,
            "recovered":recovered,
            "backoff_active":backoff_active,
            "never_connected":never_connected,
        }

    @staticmethod
    def _validate_peer_retry_seconds(value):
        if isinstance(value,bool) or not isinstance(value,(int,float)):
            raise ValueError("invalid peer retry timing")
        # Compare in the original numeric domain before float conversion so
        # arbitrarily large Python integers fail closed without OverflowError.
        if value < 0 or value > 3600:
            raise ValueError("invalid peer retry timing")
        raw=float(value)
        if not math.isfinite(raw):
            raise ValueError("invalid peer retry timing")
        return raw

    @staticmethod
    def _validate_peer_failure_count(value):
        if (
            isinstance(value,bool)
            or not isinstance(value,int)
            or value < 0
            or value > 2147483647
        ):
            raise ValueError("invalid peer failure count")
        return value

    @_peer_locked
    def set_peer_retry_schedule(self, peer, delay_seconds, base_interval=5.0):
        """Record operator-visible retry scheduling state for one peer."""
        addr=self._parse_peer(peer)
        raw_delay=self._validate_peer_retry_seconds(delay_seconds)
        raw_base=self._validate_peer_retry_seconds(base_interval)
        delay=raw_delay
        base=max(0.5,raw_base)
        self.peer_retry_delay_seconds[addr]=delay
        self.peer_retry_base_interval[addr]=base
        self.peer_next_retry_at[addr]=(
            datetime.now(timezone.utc)
            .timestamp() + delay
        )
        self.peer_next_retry_at[addr]=(
            datetime.fromtimestamp(
                self.peer_next_retry_at[addr],timezone.utc
            ).isoformat().replace("+00:00","Z")
        )

    @_peer_locked
    def clear_peer_retry_schedule(self, peer):
        """Clear operator-visible retry scheduling state for one peer."""
        addr=self._parse_peer(peer)
        self.peer_retry_delay_seconds.pop(addr,None)
        self.peer_next_retry_at.pop(addr,None)
        self.peer_retry_base_interval.pop(addr,None)

    @_peer_locked
    def peer_retry_delay(self, peer, base_interval=5.0, cap=60.0):
        """Return bounded exponential retry delay for one outbound peer."""
        addr=self._parse_peer(peer)
        raw_base=self._validate_peer_retry_seconds(base_interval)
        raw_cap=self._validate_peer_retry_seconds(cap)
        base=max(0.5,raw_base)
        ceiling=max(base,raw_cap)
        failures=self._validate_peer_failure_count(
            self.peer_consecutive_failures.get(addr,0)
        )

        # Failure #1 still uses the normal interval. Each subsequent
        # consecutive failure doubles the delay until the cap is reached.
        # Bound the exponent before arithmetic so corrupted counters cannot
        # trigger giant integer construction or overflow work.
        exponent=max(0,failures-1)
        if exponent == 0 or ceiling == base:
            return base
        saturation_exponent=max(
            0,
            int(math.ceil(math.log2(ceiling/base))),
        )
        safe_exponent=min(exponent,saturation_exponent)
        return min(ceiling,math.ldexp(base,safe_exponent))

    def sync_outbound_peer(self, peer):
        """Synchronize one configured outbound peer and update its health."""
        addr=self._parse_peer(peer)
        try:
            source_host=addr[0]
            block_gate=lambda: (
                self._outbound_sync_block_work_limiter.consume(source_host)
            )
            signature_gate=lambda cost: (
                self._outbound_sync_block_signature_work_limiter.consume(
                    source_host,cost
                )
            )
            accepted=p2p.sync_to_peer(
                addr,p2p.PeerSession(self.chain,self.mempool),limit=128,
                block_work_gate=block_gate,
                block_signature_work_gate=signature_gate,
            )
        except Exception as e:
            error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error
                    self.peer_consecutive_failures[addr]=self.peer_consecutive_failures.get(addr,0)+1
                    self.peer_last_failure_at[addr]=self._peer_health_timestamp()
                    self.record_peer_health_transition(addr)
            return {"peer":f"{addr[0]}:{addr[1]}","ok":False,
                    "error":error}

        with _peer_guard(self):
            if addr in self.outbound_peers:
                self.peer_last_error[addr]=None
                self.peer_sync_successes[addr]=self.peer_sync_successes.get(addr,0)+1
                self.peer_consecutive_failures[addr]=0
                self.peer_last_success_at[addr]=self._peer_health_timestamp()
                self.record_peer_health_transition(addr)
        return {"peer":f"{addr[0]}:{addr[1]}","ok":True,
                "accepted":accepted}

    def sync_outbound_peers(self):
        return [
            self.sync_outbound_peer(addr)
            for addr in self.outbound_peer_addresses()
        ]

    def _propagate_block_outbound(self, block):
        for addr in self.outbound_peer_addresses():
            try:
                p2p.propagate_block(addr,block)
                error=None
            except Exception as e:
                error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error

    def _propagate_tx_outbound(self, tx):
        for addr in self.outbound_peer_addresses():
            try:
                p2p.propagate_tx(addr,tx)
                error=None
            except Exception as e:
                error=f"{type(e).__name__}: {e}"
            with _peer_guard(self):
                if addr in self.outbound_peers:
                    self.peer_last_error[addr]=error

    def request_shutdown(self):
        self.shutdown_requested = True
        return {"stopping": True}

    def stop_p2p(self):
        if self.p2p_server is not None:
            self.p2p_server.stop()
            self.p2p_server = None

    def sync_peer(self, host, port, batch=128):
        addr = self._parse_peer((host, port))
        return p2p.sync_to_peer(
            addr, p2p.PeerSession(self.chain, self.mempool),
            limit=int(batch)
        )
