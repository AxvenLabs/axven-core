#!/usr/bin/env python3
import json, os, stat, tempfile
from pathlib import Path
from datadir import DataDir


def main():
    checks=0
    with tempfile.TemporaryDirectory() as td:
        dd=DataDir(td)
        legacy=dd.path/'peers.json.tmp'
        legacy.write_text('sentinel',encoding='utf-8')
        peers=[('127.0.0.1',18444),('example.org',19444)]
        dd.save_peers(peers)
        assert legacy.read_text(encoding='utf-8')=='sentinel'
        checks+=1; print('[GREEN] predictable peer temp path is not reused')
        assert dd.load_peers()==peers
        raw=json.loads(dd.peer_file.read_text(encoding='utf-8'))
        assert raw==[{'host':'127.0.0.1','port':18444},{'host':'example.org','port':19444}]
        checks+=1; print('[GREEN] canonical peer persistence round-trip preserved')
        leftovers=[p for p in dd.path.iterdir() if p.name.startswith('.peers.json.') and p.name.endswith('.tmp')]
        assert leftovers==[]
        checks+=1; print('[GREEN] successful peer save leaves no temporary file')
        if os.name=='posix':
            assert stat.S_IMODE(dd.peer_file.stat().st_mode) & 0o077 == 0
        checks+=1; print('[GREEN] peer config permissions are private where supported')
        original=__import__('datadir').os.replace
        try:
            def fail_replace(src,dst): raise OSError('simulated replace failure')
            __import__('datadir').os.replace=fail_replace
            before=dd.peer_file.read_bytes()
            try: dd.save_peers([('127.0.0.1',20000)])
            except OSError: pass
            else: raise AssertionError('replace failure did not propagate')
            assert dd.peer_file.read_bytes()==before
            leftovers=[p for p in dd.path.iterdir() if p.name.startswith('.peers.json.') and p.name.endswith('.tmp')]
            assert leftovers==[]
        finally:
            __import__('datadir').os.replace=original
        checks+=1; print('[GREEN] failed replace preserves old config and cleans temp file')
    print(f'SEC-110 peer config atomic file: {checks}/{checks} GREEN')

if __name__=='__main__': main()
