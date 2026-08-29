#!/usr/bin/env python3
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
