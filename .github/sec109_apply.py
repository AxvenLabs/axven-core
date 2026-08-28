#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

wallet_path=Path('wallet.py')
s=wallet_path.read_text(encoding='utf-8')
s=s.replace('import os\n','import os\nimport tempfile\n',1)
old='''def save_backup_file(identity, path, passphrase: str):
    data = export_backup(identity, passphrase)
    path = os.fspath(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, sort_keys=True, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
'''
new='''def save_backup_file(identity, path, passphrase: str):
    data = export_backup(identity, passphrase)
    target = Path(os.fspath(path))
    parent = target.parent if str(target.parent) else Path(".")
    fd = None
    tmp_path = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=str(parent),
            text=True,
        )
        tmp_path = Path(tmp_name)
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            json.dump(data, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
        tmp_path = None
        if os.name == "posix":
            os.chmod(target, 0o600)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
'''
if s.count(old)!=1: raise SystemExit('SEC-109 wallet target mismatch')
wallet_path.write_text(s.replace(old,new),encoding='utf-8',newline='\n')

spec=Path('security_sec109_wallet_backup_atomic_file_spec.py')
spec.write_text('''#!/usr/bin/env python3
import os, stat, tempfile
from pathlib import Path
import wallet


def main():
    checks=0
    ident=wallet.WalletIdentity()
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        target=root/'wallet-backup.json'
        legacy=root/'wallet-backup.json.tmp'
        legacy.write_text('sentinel',encoding='utf-8')
        wallet.save_backup_file(ident,target,'correct horse battery staple')
        assert legacy.read_text(encoding='utf-8')=='sentinel'
        checks+=1; print('[GREEN] predictable legacy temp path is not reused')
        restored=wallet.load_backup_file(target,'correct horse battery staple')
        assert restored.address_n==ident.address_n and restored.address_m==ident.address_m and restored.address_h==ident.address_h
        checks+=1; print('[GREEN] atomic backup round-trip preserved')
        leftovers=[p for p in root.iterdir() if p.name.startswith('.wallet-backup.json.') and p.name.endswith('.tmp')]
        assert leftovers==[]
        checks+=1; print('[GREEN] successful save leaves no temporary file')
        if os.name=='posix':
            mode=stat.S_IMODE(target.stat().st_mode)
            assert mode & 0o077 == 0
        checks+=1; print('[GREEN] backup file permissions are private where supported')
        original_replace=wallet.os.replace
        try:
            def fail_replace(src,dst): raise OSError('simulated replace failure')
            wallet.os.replace=fail_replace
            failed=root/'failed-backup.json'
            try: wallet.save_backup_file(ident,failed,'correct horse battery staple')
            except OSError: pass
            else: raise AssertionError('replace failure did not propagate')
            leftovers=[p for p in root.iterdir() if p.name.startswith('.failed-backup.json.') and p.name.endswith('.tmp')]
            assert leftovers==[] and not failed.exists()
        finally:
            wallet.os.replace=original_replace
        checks+=1; print('[GREEN] failed replace cleans temporary file')
    print(f'SEC-109 wallet backup atomic file: {checks}/{checks} GREEN')

if __name__=='__main__': main()
''',encoding='utf-8',newline='\n')

m_path=Path('release_manifest.json'); m=json.loads(m_path.read_text(encoding='utf-8'))
for name in ('wallet.py',spec.name):
    data=Path(name).read_bytes(); m['files'][name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
m['files']=dict(sorted(m['files'].items()))
m_path.write_text(json.dumps(m,indent=2,ensure_ascii=False)+'\n',encoding='utf-8',newline='\n')
