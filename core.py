#!/usr/bin/env python3
"""Axven Core service layer — checkpoint 6.

Unifies chain, mempool, wallet orchestration, mining and P2P helpers without
changing consensus.  RPC is layered on top in rpc.py.
"""
from __future__ import annotations
from typing import Optional, Tuple

import axven
import p2p
import wallet


class AxvenCore:
    def __init__(self, chain: Optional[axven.Blockchain] = None,
                 mempool: Optional[axven.Mempool] = None,
                 identity: Optional[wallet.WalletIdentity] = None):
        self.chain = chain or axven.Blockchain()
        self.mempool = mempool or axven.Mempool(self.chain)
        self.identity = identity
        self.pending = wallet.PendingTracker()
        self.p2p_server = None
        self.outbound_peers = []
        self.peer_last_error = {}
        self.shutdown_requested = False

    def require_wallet(self):
        if self.identity is None:
            raise RuntimeError("wallet not loaded")
        return self.identity

    def status(self):
        return {
            "chain_id": axven.CHAIN_ID,
            "config_fingerprint": axven.CONFIG_FINGERPRINT,
            "genesis_hash": axven._genesis().hash(),
            "height": self.chain.tip.height,
            "tip_hash": self.chain.tip.hash(),
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

    def get_block(self, block_id):
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

    def get_transaction(self, txid):
        txid=str(txid)
        if txid in self.mempool.txs:
            tx=self.mempool.txs[txid]
            return {"txid":txid,"status":"mempool","tx":tx.to_dict()}
        for block in reversed(self.chain.blocks):
            for tx in block.txs():
                if tx.txid()==txid:
                    return {
                        "txid":txid,
                        "status":"confirmed",
                        "height":block.height,
                        "block_hash":block.hash(),
                        "tx":tx.to_dict(),
                    }
        raise KeyError("transaction not found")

    def mempool_view(self, limit=100):
        limit=max(1,min(int(limit),500))
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
        st=self.status()
        st["latest_blocks"]=self.recent_blocks(10)
        st["mempool"]=self.mempool_view(20)
        st["state_root"]=axven.expected_state_root(self.chain.utxo,self.chain.tip.height)
        return st

    def chain_config(self):
        return dict(axven.CHAIN_CONFIG)

    def addresses(self):
        w = self.require_wallet()
        return {"N": w.address_n, "M": w.address_m, "H": w.address_h}

    def balance(self, scheme=None):
        w = self.require_wallet()
        if scheme is None:
            return {
                axven.SCHEME_ED25519: self.chain.balance(w.address_n),
                axven.SCHEME_ML_DSA: self.chain.balance(w.address_m),
                axven.SCHEME_HYBRID: self.chain.balance(w.address_h),
            }
        return self.chain.balance(w.address_of(scheme))

    def wallet_status(self, scheme=None):
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
        w = self.require_wallet()
        return [
            {"txid": txid, "index": idx, "amount": amount}
            for txid, idx, amount in self.chain.spendable(w.address_of(scheme))
            if not self.pending.is_reserved((txid, idx))
        ]

    def mine(self, count=1, scheme=None):
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
            self.pending.reconcile(self.mempool)
            self._propagate_block_outbound(block)
        return hashes

    def send(self, input_scheme, recipient, amount, fee):
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
        self.p2p_server = p2p.NodeServer(
            self.chain, self.mempool, host=host, port=int(port)
        ).start()
        return self.p2p_server.address

    @staticmethod
    def _parse_peer(peer):
        if isinstance(peer,(tuple,list)) and len(peer)==2:
            return (str(peer[0]),int(peer[1]))
        raw=str(peer).strip()
        if ":" not in raw:
            raise ValueError("peer must be host:port")
        host,port=raw.rsplit(":",1)
        if not host:
            raise ValueError("peer host required")
        port=int(port)
        if not 1 <= port <= 65535:
            raise ValueError("invalid peer port")
        return (host,port)

    def add_outbound_peer(self, peer):
        addr=self._parse_peer(peer)
        if addr not in self.outbound_peers:
            self.outbound_peers.append(addr)
        return addr

    def outbound_peer_status(self):
        return [
            {
                "host":host,
                "port":port,
                "last_error":self.peer_last_error.get((host,port)),
            }
            for host,port in self.outbound_peers
        ]

    def sync_outbound_peers(self):
        results=[]
        for addr in list(self.outbound_peers):
            try:
                accepted=p2p.sync_to_peer(
                    addr,p2p.PeerSession(self.chain,self.mempool),limit=128
                )
                self.peer_last_error[addr]=None
                results.append({"peer":f"{addr[0]}:{addr[1]}","ok":True,
                                "accepted":accepted})
            except Exception as e:
                self.peer_last_error[addr]=f"{type(e).__name__}: {e}"
                results.append({"peer":f"{addr[0]}:{addr[1]}","ok":False,
                                "error":self.peer_last_error[addr]})
        return results

    def _propagate_block_outbound(self, block):
        for addr in list(self.outbound_peers):
            try:
                p2p.propagate_block(addr,block)
                self.peer_last_error[addr]=None
            except Exception as e:
                self.peer_last_error[addr]=f"{type(e).__name__}: {e}"

    def _propagate_tx_outbound(self, tx):
        for addr in list(self.outbound_peers):
            try:
                p2p.propagate_tx(addr,tx)
                self.peer_last_error[addr]=None
            except Exception as e:
                self.peer_last_error[addr]=f"{type(e).__name__}: {e}"

    def request_shutdown(self):
        self.shutdown_requested = True
        return {"stopping": True}

    def stop_p2p(self):
        if self.p2p_server is not None:
            self.p2p_server.stop()
            self.p2p_server = None

    def sync_peer(self, host, port, batch=128):
        return p2p.sync_to_peer(
            (host, int(port)), p2p.PeerSession(self.chain, self.mempool),
            limit=int(batch)
        )
