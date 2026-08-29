from pathlib import Path
import hashlib
import json

EXPLORER = Path("explorer.py")
text = EXPLORER.read_text(encoding="utf-8")

old = "from urllib.parse import urlparse, parse_qs\n"
new = "from urllib.parse import urlparse\n"
if old not in text:
    raise SystemExit("import anchor missing")
text = text.replace(old, new, 1)

old = '_ALLOWED_EXPLORER_HOSTS={"127.0.0.1","localhost","::1"}\n'
new = old + 'MAX_EXPLORER_QUERY_CHARS=1024\n'
if old not in text:
    raise SystemExit("constant anchor missing")
text = text.replace(old, new, 1)

anchor = '''    if host not in _ALLOWED_EXPLORER_HOSTS:\n        raise ValueError("invalid host header")\n\n\ndef _json(handler,status,obj):\n'''
replacement = '''    if host not in _ALLOWED_EXPLORER_HOSTS:\n        raise ValueError("invalid host header")\n\n\ndef _validate_explorer_query_budget(raw_query):\n    # Request targets are attacker-controlled browser/process input even on\n    # loopback. Keep query work bounded before any field parsing or core call.\n    if type(raw_query) is not str:\n        raise ValueError("invalid Explorer query")\n    if len(raw_query) > MAX_EXPLORER_QUERY_CHARS:\n        raise ValueError("Explorer query too long")\n    return raw_query\n\n\ndef _parse_explorer_limit_query(raw_query, default, maximum):\n    # Explorer currently exposes one optional query field: limit. Parse its\n    # wire form directly so percent-encoding, Unicode digits, signs, numeric\n    # separators, duplicate fields, and custom parser aliases cannot reach\n    # int() or the service layer as alternate numeric representations.\n    raw_query=_validate_explorer_query_budget(raw_query)\n    if not raw_query:\n        return default\n    prefix="limit="\n    if not raw_query.startswith(prefix) or raw_query.count("=") != 1:\n        raise ValueError("invalid Explorer query")\n    value_text=raw_query[len(prefix):]\n    if (\n        not value_text\n        or len(value_text) > 3\n        or not value_text.isascii()\n        or not value_text.isdigit()\n        or (len(value_text) > 1 and value_text.startswith("0"))\n    ):\n        raise ValueError("invalid Explorer limit")\n    value=int(value_text)\n    if value < 1 or value > maximum:\n        raise ValueError("invalid Explorer limit")\n    return value\n\n\ndef _json(handler,status,obj):\n'''
if anchor not in text:
    raise SystemExit("helper anchor missing")
text = text.replace(anchor, replacement, 1)

old = '''                u=urlparse(self.path)\n                path=u.path\n                q=parse_qs(u.query)\n'''
new = '''                u=urlparse(self.path)\n                _validate_explorer_query_budget(u.query)\n                path=u.path\n'''
if old not in text:
    raise SystemExit("handler query anchor missing")
text = text.replace(old, new, 1)

old = '''                if path=="/api/blocks":\n                    limit=int((q.get("limit") or ["20"])[0])\n                    _json(self,200,{"ok":True,"result":core.recent_blocks(limit)}); return\n'''
new = '''                if path=="/api/blocks":\n                    limit=_parse_explorer_limit_query(u.query,20,200)\n                    _json(self,200,{"ok":True,"result":core.recent_blocks(limit)}); return\n'''
if old not in text:
    raise SystemExit("blocks anchor missing")
text = text.replace(old, new, 1)

old = '''                if path=="/api/mempool":\n                    limit=int((q.get("limit") or ["100"])[0])\n                    _json(self,200,{"ok":True,"result":core.mempool_view(limit)}); return\n'''
new = '''                if path=="/api/mempool":\n                    limit=_parse_explorer_limit_query(u.query,100,500)\n                    _json(self,200,{"ok":True,"result":core.mempool_view(limit)}); return\n'''
if old not in text:
    raise SystemExit("mempool anchor missing")
text = text.replace(old, new, 1)

EXPLORER.write_bytes(text.encode("utf-8"))

spec = r'''#!/usr/bin/env python3
"""SEC-148: bound and canonicalize Explorer query parsing before core work."""
import inspect
import socket

import axven
import explorer


class ProbeCore:
    def __init__(self):
        self.recent_calls=[]
        self.mempool_calls=[]

    def recent_blocks(self,limit):
        self.recent_calls.append(limit)
        return []

    def mempool_view(self,limit):
        self.mempool_calls.append(limit)
        return {"size":0,"transactions":[]}

    def explorer_summary(self):
        return {"height":0,"chain_id":axven.CHAIN_ID}


def request(address,path):
    port=address[1]
    raw=(
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    sock=socket.create_connection(address,timeout=1.0)
    try:
        sock.settimeout(2.0)
        sock.sendall(raw)
        response=b""
        while True:
            chunk=sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response
    finally:
        sock.close()


def status(response):
    return int(response.split(b" ",2)[1])


def main():
    checks=[]

    def green(name,condition):
        assert condition,name
        checks.append(name)
        print("[GREEN]",name)

    def reject(query,default=20,maximum=200):
        try:
            explorer._parse_explorer_limit_query(query,default,maximum)
        except ValueError:
            return True
        return False

    green(
        "Explorer query character budget pinned tightly",
        explorer.MAX_EXPLORER_QUERY_CHARS == 1024,
    )
    green(
        "empty block query preserves default limit",
        explorer._parse_explorer_limit_query("",20,200) == 20,
    )
    green(
        "canonical block limit preserved",
        explorer._parse_explorer_limit_query("limit=20",20,200) == 20,
    )
    green(
        "maximum block limit preserved",
        explorer._parse_explorer_limit_query("limit=200",20,200) == 200,
    )
    green(
        "maximum mempool limit preserved",
        explorer._parse_explorer_limit_query("limit=500",100,500) == 500,
    )

    invalid_queries=(
        "limit=+20",
        "limit=020",
        "limit=2_0",
        "limit=%32%30",
        "limit=٢٠",
        "limit=0",
        "limit=201",
        "limit=20&limit=21",
        "other=20",
        "limit=",
        "limit=1.0",
    )
    for query in invalid_queries:
        green(
            f"noncanonical Explorer limit rejected: {query!r}",
            reject(query),
        )

    green(
        "oversized Explorer query rejected before parsing",
        reject("limit=" + "1" * explorer.MAX_EXPLORER_QUERY_CHARS),
    )

    core=ProbeCore()
    server=explorer.ExplorerServer(core,port=0).start()
    try:
        response=request(server.address,"/api/blocks?limit=20")
        green(
            "canonical block query reaches core exactly",
            status(response) == 200 and core.recent_calls == [20],
        )
        baseline=len(core.recent_calls)
        for path in (
            "/api/blocks?limit=020",
            "/api/blocks?limit=%32%30",
            "/api/blocks?limit=20&limit=21",
            "/api/blocks?other=20",
        ):
            response=request(server.address,path)
            green(
                f"noncanonical HTTP block query rejected pre-core: {path}",
                status(response) == 400 and len(core.recent_calls) == baseline,
            )

        long_path="/api/blocks?" + ("a" * (explorer.MAX_EXPLORER_QUERY_CHARS + 1))
        response=request(server.address,long_path)
        green(
            "oversized HTTP query rejected before core work",
            status(response) == 400 and len(core.recent_calls) == baseline,
        )

        response=request(server.address,"/api/mempool?limit=500")
        green(
            "canonical mempool query reaches core exactly",
            status(response) == 200 and core.mempool_calls == [500],
        )
    finally:
        server.stop()

    handler_src=inspect.getsource(explorer._handler)
    parser_src=inspect.getsource(explorer._parse_explorer_limit_query)
    green(
        "production handler bounds query before route dispatch",
        "_validate_explorer_query_budget(u.query)" in handler_src,
    )
    green(
        "unbounded parse_qs allocation removed from Explorer",
        "parse_qs" not in inspect.getsource(explorer),
    )
    green(
        "attacker numeric aliases are rejected before int conversion",
        "value_text.isascii()" in parser_src
        and "value_text.isdigit()" in parser_src
        and parser_src.index("value=int(value_text)") > parser_src.index("value_text.isascii()"),
    )
    green(
        "Explorer query hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-148 Explorer query domain: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
SPEC = Path("security_sec148_explorer_query_domain_spec.py")
SPEC.write_bytes(spec.encode("utf-8"))

manifest_path=Path("release_manifest.json")
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
for path in (EXPLORER,SPEC):
    data=path.read_bytes()
    manifest["files"][path.as_posix()]={
        "bytes":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_bytes((json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8"))

print("SEC-148 patch staged")