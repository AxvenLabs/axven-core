#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

core_path=Path("core.py")
source=core_path.read_text(encoding="utf-8")

old='''    def get_transaction(self, txid):
        with self.chain._state_lock:
            return self._get_transaction_locked(txid)

    def _refresh_confirmed_tx_index_locked(self):
'''
new='''    @staticmethod
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
'''
if source.count(old)!=1:
    raise SystemExit("SEC-137 public lookup anchor mismatch")
source=source.replace(old,new,1)

old_locked='''    def _get_transaction_locked(self, txid):
        txid=str(txid)
        if len(txid) > 64:
            raise ValueError("transaction id too long")
        with _mempool_guard(self.mempool):
'''
new_locked='''    def _get_transaction_locked(self, txid):
        txid=self._validate_transaction_id(txid)
        with _mempool_guard(self.mempool):
'''
if source.count(old_locked)!=1:
    raise SystemExit("SEC-137 locked lookup anchor mismatch")
source=source.replace(old_locked,new_locked,1)
core_path.write_text(source,encoding="utf-8")

spec=r'''#!/usr/bin/env python3
"""SEC-137 requires canonical transaction ids before chain-lock acquisition."""

import inspect

import axven
import core as core_module


class ProbeLock:
    def __init__(self):
        self.entries=0

    def __enter__(self):
        self.entries+=1
        return self

    def __exit__(self,exc_type,exc,tb):
        return False


class FakeChain:
    def __init__(self):
        self._state_lock=ProbeLock()
        self.blocks=[]


class FakeMempool:
    def __init__(self):
        self.txs={}


def make_core():
    service=object.__new__(core_module.AxvenCore)
    service.chain=FakeChain()
    service.mempool=FakeMempool()
    return service


def main():
    checks=[]

    def green(name,condition):
        assert condition,name
        checks.append(name)
        print("[GREEN]",name)

    service=make_core()
    malformed=(
        "a"*63,
        "a"*65,
        "A"*64,
        "g"*64,
        "0x"+("a"*62),
        0,
        True,
        None,
        ["a"*64],
    )
    for value in malformed:
        before=service.chain._state_lock.entries
        try:
            service.get_transaction(value)
        except ValueError:
            rejected=True
        else:
            rejected=False
        green(
            f"malformed transaction id rejected before state lock: {type(value).__name__}",
            rejected and service.chain._state_lock.entries == before,
        )

    canonical="f"*64
    before=service.chain._state_lock.entries
    try:
        service.get_transaction(canonical)
    except KeyError:
        normal_miss=True
    else:
        normal_miss=False
    green(
        "canonical lowercase 64-hex transaction id reaches normal lookup",
        normal_miss and service.chain._state_lock.entries == before+1,
    )

    try:
        service._get_transaction_locked("F"*64)
    except ValueError:
        direct_guard=True
    else:
        direct_guard=False
    green(
        "locked helper independently rejects noncanonical transaction aliases",
        direct_guard,
    )

    public_src=inspect.getsource(core_module.AxvenCore.get_transaction)
    validator_src=inspect.getsource(core_module.AxvenCore._validate_transaction_id)
    green(
        "production validates transaction id before acquiring chain state lock",
        public_src.index("_validate_transaction_id")
        < public_src.index("with self.chain._state_lock"),
    )
    green(
        "transaction id domain is exact lowercase SHA-256 hex",
        "len(txid) > 64" in validator_src
        and "len(txid) != 64" in validator_src
        and '"0123456789abcdef"' in validator_src
        and "not isinstance(txid,str)" in validator_src,
    )
    green(
        "transaction id hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-137 canonical transaction id pre-lock: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
spec_path=Path("security_sec137_canonical_txid_prelock_spec.py")
spec_path.write_text(spec,encoding="utf-8")

# Hash the LF-normalized bytes Git stores in canonical blobs, not the CRLF
# checkout representation used by Windows runners.
def git_blob_bytes(path):
    text=Path(path).read_text(encoding="utf-8")
    return text.replace("\r\n","\n").encode("utf-8")

manifest_path=Path("release_manifest.json")
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("core.py",spec_path.name):
    raw=git_blob_bytes(name)
    manifest["files"][name]={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
manifest_text=json.dumps(manifest,indent=2,sort_keys=True,ensure_ascii=False)+"\n"
manifest_path.write_text(manifest_text,encoding="utf-8",newline="\n")
