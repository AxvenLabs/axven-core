#!/usr/bin/env python3
from __future__ import annotations
import os
import tempfile
from pathlib import Path
import axven, wallet
from core import AxvenCore

# Persisted peer configuration is small operator metadata, not chain state.
# Keep enough room for MAX_CONFIGURED_PEERS entries even when 255-character
# Unicode hosts expand under json.dumps(ensure_ascii=True).
MAX_PEER_CONFIG_BYTES = 1024 * 1024
MAX_PEER_CONFIG_JSON_NESTING_DEPTH = 16
MAX_PEER_CONFIG_JSON_STRUCTURAL_ITEMS = 1024


def _preflight_peer_config_json(raw):
    """Bound persisted peer JSON structure before recursive parser allocation."""
    if type(raw) is not bytes:
        raise ValueError("invalid peer config")
    stack=[]
    structural_items=0
    in_string=False
    escaped=False
    for byte in raw:
        if in_string:
            if escaped:
                escaped=False
            elif byte == 0x5C:  # backslash
                escaped=True
            elif byte == 0x22:  # quote
                in_string=False
            continue

        if byte == 0x22:
            in_string=True
            continue
        if byte in (0x7B,0x5B):  # { [
            structural_items += 1
            if structural_items > MAX_PEER_CONFIG_JSON_STRUCTURAL_ITEMS:
                raise ValueError("peer config JSON too complex")
            stack.append(byte)
            if len(stack) > MAX_PEER_CONFIG_JSON_NESTING_DEPTH:
                raise ValueError("peer config JSON nesting too deep")
            continue
        if byte == 0x2C and stack:  # comma between container members/items
            structural_items += 1
            if structural_items > MAX_PEER_CONFIG_JSON_STRUCTURAL_ITEMS:
                raise ValueError("peer config JSON too complex")
            continue
        if byte in (0x7D,0x5D):  # } ]
            expected=0x7B if byte == 0x7D else 0x5B
            if stack and stack[-1] == expected:
                stack.pop()


def _reject_duplicate_peer_json_keys(pairs):
    obj={}
    for key,value in pairs:
        if key in obj:
            raise ValueError(f"duplicate peer config JSON key: {key}")
        obj[key]=value
    return obj


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
        with open(self.peer_file,"rb") as f:
            encoded=f.read(MAX_PEER_CONFIG_BYTES + 1)
        if len(encoded) > MAX_PEER_CONFIG_BYTES:
            raise ValueError("peer config too large")
        _preflight_peer_config_json(encoded)
        try:
            raw=json.loads(
                encoded.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_peer_json_keys,
            )
        except (UnicodeError,json.JSONDecodeError,RecursionError) as exc:
            raise ValueError("invalid peer config") from exc
        if not isinstance(raw,list):
            raise ValueError("peer config must be a list")
        if len(raw) > AxvenCore.MAX_CONFIGURED_PEERS:
            raise ValueError("too many configured peers")
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
            if len(normalized) >= AxvenCore.MAX_CONFIGURED_PEERS:
                raise ValueError("too many configured peers")
            host,port=AxvenCore._parse_peer(peer)
            normalized.append({"host":host,"port":port})
        payload=(json.dumps(normalized,indent=2,sort_keys=True)+"\n").encode("utf-8")
        if len(payload) > MAX_PEER_CONFIG_BYTES:
            raise ValueError("peer config too large")
        fd=None
        tmp_path=None
        try:
            fd,tmp_name=tempfile.mkstemp(
                prefix=f".{self.peer_file.name}.",
                suffix=".tmp",
                dir=str(self.peer_file.parent),
                text=True,
            )
            tmp_path=Path(tmp_name)
            if os.name=="posix":
                os.fchmod(fd,0o600)
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                fd=None
                f.write(payload.decode("utf-8"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path,self.peer_file)
            tmp_path=None
            if os.name=="posix":
                os.chmod(self.peer_file,0o600)
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except FileNotFoundError:
                    pass

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
