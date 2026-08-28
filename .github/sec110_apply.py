#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

path=Path('datadir.py')
s=path.read_text(encoding='utf-8')
s=s.replace('import os\n','import os\nimport tempfile\n',1)
old='''    def save_peers(self,peers):
        import json
        normalized=[]
        for peer in peers:
            host,port=AxvenCore._parse_peer(peer)
            normalized.append({"host":host,"port":port})
        tmp=self.peer_file.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(normalized,indent=2,sort_keys=True)+"\\n",
            encoding="utf-8"
        )
        os.replace(tmp,self.peer_file)
'''
new='''    def save_peers(self,peers):
        import json
        normalized=[]
        for peer in peers:
            host,port=AxvenCore._parse_peer(peer)
            normalized.append({"host":host,"port":port})
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
                f.write(json.dumps(normalized,indent=2,sort_keys=True)+"\\n")
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
'''
if s.count(old)!=1: raise SystemExit('SEC-110 datadir target mismatch')
path.write_text(s.replace(old,new),encoding='utf-8',newline='\n')

spec=Path('security_sec110_peer_config_atomic_file_spec.py')
spec.write_text('''#!/usr/bin/env python3
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
''',encoding='utf-8',newline='\n')

m_path=Path('release_manifest.json'); m=json.loads(m_path.read_text(encoding='utf-8'))
for name in ('datadir.py',spec.name):
    data=Path(name).read_bytes(); m['files'][name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
m['files']=dict(sorted(m['files'].items()))
m_path.write_text(json.dumps(m,indent=2,ensure_ascii=False)+'\n',encoding='utf-8',newline='\n')
