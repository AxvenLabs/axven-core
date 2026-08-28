#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

path=Path('axven.py')
s=path.read_text(encoding='utf-8')
old_import='import base64, hashlib, json\nimport threading\n'
new_import='import base64, hashlib, json, os, tempfile\nimport threading\nfrom pathlib import Path\n'
if s.count(old_import)!=1: raise SystemExit('SEC-111 import target mismatch')
s=s.replace(old_import,new_import,1)
old='''    def persist(self, chain: Blockchain):
        payload = {
            "chain_id": CHAIN_ID,
            "config_fingerprint": CONFIG_FINGERPRINT,
            "blocks": [b.to_dict() for b in chain.blocks],
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        os.replace(tmp, self.path)
'''
new='''    def persist(self, chain: Blockchain):
        payload = {
            "chain_id": CHAIN_ID,
            "config_fingerprint": CONFIG_FINGERPRINT,
            "blocks": [b.to_dict() for b in chain.blocks],
        }
        fd = None
        tmp_path = None
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=str(self.directory),
                text=True,
            )
            tmp_path = Path(tmp_name)
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                f.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
            tmp_path = None
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except FileNotFoundError:
                    pass
'''
if s.count(old)!=1: raise SystemExit('SEC-111 StateStore target mismatch')
path.write_text(s.replace(old,new),encoding='utf-8',newline='\n')

spec=Path('security_sec111_chain_state_atomic_file_spec.py')
spec.write_text('''#!/usr/bin/env python3
import tempfile
from pathlib import Path
import axven


def main():
    checks=0
    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td)
        legacy=Path(td)/'chain.tmp'
        legacy.write_text('sentinel',encoding='utf-8')

        chain=axven.Blockchain()
        wallet=axven.Wallet()
        chain.mine(wallet.address)
        expected_tip=chain.tip.hash()
        expected_utxo=dict(chain.utxo)
        store.persist(chain)

        assert legacy.read_text(encoding='utf-8')=='sentinel'
        checks+=1; print('[GREEN] predictable legacy chain temp path is not reused')

        loaded=store.load()
        assert loaded.tip.hash()==expected_tip
        assert loaded.utxo==expected_utxo
        assert loaded.validate()
        checks+=1; print('[GREEN] canonical chain persistence round-trip preserved')

        leftovers=[p for p in Path(td).iterdir() if p.name.startswith('.chain.json.') and p.name.endswith('.tmp')]
        assert leftovers==[]
        checks+=1; print('[GREEN] successful chain persist leaves no temporary file')

        before=store.path.read_bytes()
        chain.mine(wallet.address)
        original_replace=axven.os.replace
        try:
            def fail_replace(src,dst): raise OSError('simulated replace failure')
            axven.os.replace=fail_replace
            try: store.persist(chain)
            except OSError: pass
            else: raise AssertionError('replace failure did not propagate')
        finally:
            axven.os.replace=original_replace
        assert store.path.read_bytes()==before
        leftovers=[p for p in Path(td).iterdir() if p.name.startswith('.chain.json.') and p.name.endswith('.tmp')]
        assert leftovers==[]
        checks+=1; print('[GREEN] failed replace preserves old chain and cleans temp file')

        reloaded=store.load()
        assert reloaded.tip.hash()==expected_tip and reloaded.validate()
        checks+=1; print('[GREEN] old persisted chain remains loadable after failed update')

    print(f'SEC-111 chain state atomic file: {checks}/{checks} GREEN')

if __name__=='__main__': main()
''',encoding='utf-8',newline='\n')

m_path=Path('release_manifest.json'); m=json.loads(m_path.read_text(encoding='utf-8'))
for name in ('axven.py',spec.name):
    data=Path(name).read_bytes(); m['files'][name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
m['files']=dict(sorted(m['files'].items()))
m_path.write_text(json.dumps(m,indent=2,ensure_ascii=False)+'\n',encoding='utf-8',newline='\n')
