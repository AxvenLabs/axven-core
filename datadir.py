#!/usr/bin/env python3
from __future__ import annotations
import os
import secrets
import stat
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
RPC_TOKEN_HEX_LENGTH = 64
MAX_RPC_TOKEN_FILE_BYTES = RPC_TOKEN_HEX_LENGTH + 1


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


def _fsync_directory(directory):
    """Persist an atomic peer-config rename in its parent directory on POSIX."""
    if os.name != "posix":
        return
    flags=os.O_RDONLY
    if hasattr(os,"O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    dir_fd=os.open(os.fspath(directory),flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _read_secure_rpc_token_file(path):
    """Read rpc.token without trusting path indirection or unsafe metadata."""
    path=os.fspath(path)
    try:
        before=os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(before.st_mode):
        raise ValueError("unsafe RPC token file")

    flags=os.O_RDONLY
    if hasattr(os,"O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os,"O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd=None
    try:
        try:
            fd=os.open(path,flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError("unsafe RPC token file") from exc
        current=os.fstat(fd)
        if not stat.S_ISREG(current.st_mode):
            raise ValueError("unsafe RPC token file")
        if (before.st_dev,before.st_ino)!=(current.st_dev,current.st_ino):
            raise ValueError("RPC token file changed during open")
        if getattr(current,"st_nlink",1)!=1:
            raise ValueError("unsafe RPC token hardlink count")
        if os.name=="posix":
            if current.st_mode & 0o077:
                raise ValueError("RPC token file permissions must be owner-only")
            if hasattr(os,"getuid") and current.st_uid!=os.getuid():
                raise ValueError("RPC token file owner mismatch")
        with os.fdopen(fd,"rb") as f:
            fd=None
            raw=f.read(MAX_RPC_TOKEN_FILE_BYTES+1)
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw)>MAX_RPC_TOKEN_FILE_BYTES:
        raise ValueError("invalid RPC token file")
    return raw


class DataDir:
    def __init__(self,path):
        self.path=Path(path).expanduser().resolve()
        self.path.mkdir(parents=True,exist_ok=True)
        self.chain_dir=self.path/"chain"
        self.wallet_file=self.path/"wallet.json"
        self.peer_file=self.path/"peers.json"
        self.rpc_token_file=self.path/"rpc.token"

    @staticmethod
    def _validate_rpc_token(raw):
        if type(raw) is not bytes:
            raise ValueError("invalid RPC token file")
        if raw.endswith(b"\n"):
            raw=raw[:-1]
        if len(raw) != RPC_TOKEN_HEX_LENGTH:
            raise ValueError("invalid RPC token file")
        try:
            token=raw.decode("ascii")
        except UnicodeError as exc:
            raise ValueError("invalid RPC token file") from exc
        if any(ch not in "0123456789abcdef" for ch in token):
            raise ValueError("invalid RPC token file")
        return token

    def load_rpc_token(self):
        raw=_read_secure_rpc_token_file(self.rpc_token_file)
        if raw is None:
            return None
        return self._validate_rpc_token(raw)

    def load_or_create_rpc_token(self):
        existing=self.load_rpc_token()
        if existing is not None:
            return existing
        token=secrets.token_hex(32)
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
        try:
            fd=os.open(os.fspath(self.rpc_token_file),flags,0o600)
        except FileExistsError:
            # A concurrent node using the same datadir won the create race.
            # The retry must produce a canonical token or abort; returning
            # None here would disable RPC authentication in production.
            existing=self.load_rpc_token()
            if existing is None:
                raise RuntimeError("RPC token creation race left no token")
            return existing
        try:
            with os.fdopen(fd,"wb") as f:
                fd=None
                f.write(token.encode("ascii")+b"\n")
                f.flush()
                os.fsync(f.fileno())
            if os.name=="posix":
                os.chmod(self.rpc_token_file,0o600)
            _fsync_directory(self.rpc_token_file.parent)
        finally:
            if fd is not None:
                os.close(fd)
        return token

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
                if set(peer) != {"host","port"}:
                    raise ValueError("unknown peer entry field")
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
            _fsync_directory(self.peer_file.parent)
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
