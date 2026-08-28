#!/usr/bin/env python3
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
