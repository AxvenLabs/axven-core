#!/usr/bin/env python3
from __future__ import annotations
import os
from pathlib import Path
import axven, wallet
from core import AxvenCore

class DataDir:
    def __init__(self,path):
        self.path=Path(path).expanduser().resolve()
        self.path.mkdir(parents=True,exist_ok=True)
        self.chain_dir=self.path/"chain"
        self.wallet_file=self.path/"wallet.json"
        self.peer_file=self.path/"peers.json"

    def has_wallet(self):
        return self.wallet_file.exists()

    def create_wallet(self,passphrase):
        if self.wallet_file.exists():
            raise FileExistsError("wallet already exists")
        ident=wallet.WalletIdentity()
        wallet.save_backup_file(ident,self.wallet_file,passphrase)
        return ident

    def load_wallet(self,passphrase):
        if not self.wallet_file.exists():
            return None
        return wallet.load_backup_file(self.wallet_file,passphrase)

    def load_chain(self):
        chain_file=self.chain_dir/"chain.json"
        if chain_file.exists():
            return axven.StateStore(str(self.chain_dir)).load()
        return axven.Blockchain()

    def save_chain(self,chain):
        axven.StateStore(str(self.chain_dir)).persist(chain)

    def load_peers(self):
        if not self.peer_file.exists():
            return []
        import json
        raw=json.loads(self.peer_file.read_text(encoding="utf-8"))
        if not isinstance(raw,list):
            raise ValueError("peer config must be a list")
        peers=[]
        for peer in raw:
            if isinstance(peer,dict):
                if "host" not in peer or "port" not in peer:
                    raise ValueError("peer entry requires host and port")
                peer=(peer["host"],peer["port"])
            peers.append(AxvenCore._parse_peer(peer))
        return peers

    def save_peers(self,peers):
        import json
        normalized=[]
        for peer in peers:
            host,port=AxvenCore._parse_peer(peer)
            normalized.append({"host":host,"port":port})
        tmp=self.peer_file.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(normalized,indent=2,sort_keys=True)+"\n",
            encoding="utf-8"
        )
        os.replace(tmp,self.peer_file)

    def load_core(self,passphrase=None):
        chain=self.load_chain()
        mempool=axven.Mempool(chain)
        ident=None
        if self.wallet_file.exists():
            if not passphrase:
                raise ValueError("wallet passphrase required")
            ident=self.load_wallet(passphrase)
        core=AxvenCore(chain=chain,mempool=mempool,identity=ident)
        for peer in self.load_peers():
            core.add_outbound_peer(peer)
        core.peer_persist_callback=self.save_peers
        return core
