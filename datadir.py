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

    def load_core(self,passphrase=None):
        chain=self.load_chain()
        mempool=axven.Mempool(chain)
        ident=None
        if self.wallet_file.exists():
            if not passphrase:
                raise ValueError("wallet passphrase required")
            ident=self.load_wallet(passphrase)
        return AxvenCore(chain=chain,mempool=mempool,identity=ident)
