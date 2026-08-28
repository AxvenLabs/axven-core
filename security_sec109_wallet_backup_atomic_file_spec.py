#!/usr/bin/env python3
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
