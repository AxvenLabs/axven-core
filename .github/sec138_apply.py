#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

core_path=Path("core.py")
source=core_path.read_text(encoding="utf-8")
old='''    def get_block(self, block_id):
        with self.chain._state_lock:
            return self._get_block_locked(block_id)

    def _get_block_locked(self, block_id):
        block=None
        if isinstance(block_id, str) and len(block_id) > 64:
            raise ValueError("block id too long")
        if isinstance(block_id,int) or (isinstance(block_id,str) and block_id.isdigit()):
'''
new='''    @staticmethod
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
'''
if source.count(old)!=1:
    raise SystemExit("SEC-138 block lookup anchor mismatch")
source=source.replace(old,new,1)
core_path.write_text(source,encoding="utf-8")

spec=r'''#!/usr/bin/env python3
"""SEC-138 validates block lookup ids before chain-state lock acquisition."""

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
        self.index={}


def make_core():
    service=object.__new__(core_module.AxvenCore)
    service.chain=FakeChain()
    return service


def expect_prelock_reject(service,value,label,message=None):
    before=service.chain._state_lock.entries
    try:
        service.get_block(value)
    except ValueError as exc:
        ok=(message is None or str(exc)==message)
    else:
        ok=False
    assert ok and service.chain._state_lock.entries==before,label
    print("[GREEN]",label)


def expect_normal_miss(service,value,label):
    before=service.chain._state_lock.entries
    try:
        service.get_block(value)
    except KeyError:
        ok=True
    else:
        ok=False
    assert ok and service.chain._state_lock.entries==before+1,label
    print("[GREEN]",label)


def main():
    checks=0
    service=make_core()

    rejects=(
        (["a"*64],"list block id rejected before state lock"),
        ({"id":"a"*64},"object block id rejected before state lock"),
        (None,"null block id rejected before state lock"),
        (True,"boolean block id rejected before state lock"),
        (1.0,"float block id rejected before state lock"),
    )
    for value,label in rejects:
        expect_prelock_reject(service,value,label)
        checks+=1

    expect_prelock_reject(
        service,"z"*65,"oversized block string rejected before state lock",
        "block id too long",
    ); checks+=1
    expect_prelock_reject(
        service,"z"*1_000_000,"extreme block string rejected before state lock",
        "block id too long",
    ); checks+=1

    # Preserve the exact legacy lookup domain protected by SEC-053/SEC-056.
    expect_normal_miss(
        service,"z"*64,"maximum non-numeric block string still reaches normal lookup",
    ); checks+=1
    expect_normal_miss(
        service,"100","bounded numeric block string still reaches normal lookup",
    ); checks+=1
    expect_normal_miss(
        service,0,"built-in integer block height still reaches normal lookup",
    ); checks+=1

    try:
        service._get_block_locked(False)
    except ValueError:
        direct_guard=True
    else:
        direct_guard=False
    assert direct_guard,"locked helper independently rejects coercion aliases"
    print("[GREEN] locked helper independently rejects coercion aliases"); checks+=1

    public_src=inspect.getsource(core_module.AxvenCore.get_block)
    validator_src=inspect.getsource(core_module.AxvenCore._validate_block_id)
    assert (
        public_src.index("_validate_block_id")
        < public_src.index("with self.chain._state_lock")
    ),"production validates block id before chain state lock"
    print("[GREEN] production validates block id before chain state lock"); checks+=1

    assert (
        "type(block_id) is int" in validator_src
        and "type(block_id) is not str" in validator_src
        and "len(block_id) > 64" in validator_src
    ),"block id domain is exact built-in int or bounded string"
    print("[GREEN] block id domain is exact built-in int or bounded string"); checks+=1

    assert (
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    ),"block id hardening leaves canonical chain identity unchanged"
    print("[GREEN] block id hardening leaves canonical chain identity unchanged"); checks+=1

    print(f"SEC-138 block id pre-lock domain: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
'''
spec_path=Path("security_sec138_block_id_prelock_domain_spec.py")
spec_path.write_text(spec,encoding="utf-8")

# Manifest hashes refer to canonical LF Git blob bytes, not Windows CRLF checkout bytes.
def git_blob_bytes(path):
    text=Path(path).read_text(encoding="utf-8")
    return text.replace("\r\n","\n").encode("utf-8")

manifest_path=Path("release_manifest.json")
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("core.py",spec_path.name):
    raw=git_blob_bytes(name)
    manifest["files"][name]={
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest,indent=2,sort_keys=True,ensure_ascii=False)+"\n",
    encoding="utf-8",newline="\n",
)
