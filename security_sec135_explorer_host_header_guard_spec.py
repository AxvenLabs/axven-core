#!/usr/bin/env python3
"""SEC-135 blocks DNS-rebinding Host headers at the loopback Explorer boundary."""

import inspect
import socket

import axven
import explorer


class ProbeCore:
    def __init__(self):
        self.summary_calls=0

    def explorer_summary(self):
        self.summary_calls += 1
        return {"height":0,"chain_id":axven.CHAIN_ID}


def request(address,host_lines,path="/api/summary"):
    raw=b"GET "+path.encode("ascii")+b" HTTP/1.1\r\n"
    for line in host_lines:
        raw += b"Host: "+line.encode("ascii")+b"\r\n"
    raw += b"Connection: close\r\n\r\n"

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

    core=ProbeCore()
    server=explorer.ExplorerServer(core,port=0).start()
    port=server.address[1]
    try:
        response=request(server.address,[f"attacker.example:{port}"])
        green(
            "foreign Host rejected before Explorer dispatch",
            status(response) == 400 and core.summary_calls == 0,
        )

        response=request(
            server.address,
            [f"127.0.0.1.attacker.example:{port}"],
        )
        green(
            "loopback-lookalike Host rejected",
            status(response) == 400 and core.summary_calls == 0,
        )

        response=request(
            server.address,
            [f"localhost:{port}",f"127.0.0.1:{port}"],
        )
        green(
            "duplicate Host headers rejected",
            status(response) == 400 and core.summary_calls == 0,
        )

        response=request(server.address,[])
        green(
            "missing Host rejected",
            status(response) == 400 and core.summary_calls == 0,
        )

        response=request(server.address,[f"evil@localhost:{port}"])
        green(
            "userinfo-style Host rejected",
            status(response) == 400 and core.summary_calls == 0,
        )

        response=request(server.address,[f"127.0.0.1:{port}"])
        green(
            "canonical IPv4 loopback Host preserved",
            status(response) == 200 and core.summary_calls == 1,
        )

        response=request(server.address,[f"localhost:{port}"])
        green(
            "canonical localhost Host preserved",
            status(response) == 200 and core.summary_calls == 2,
        )

        response=request(server.address,[f"[::1]:{port}"])
        green(
            "canonical bracketed IPv6 loopback Host preserved",
            status(response) == 200 and core.summary_calls == 3,
        )
    finally:
        server.stop()

    handler_src=inspect.getsource(explorer._handler)
    guard_src=inspect.getsource(explorer._require_safe_explorer_host)
    do_get=handler_src[handler_src.index("def do_GET(self):"):]
    green(
        "Host guard executes before Explorer core dispatch",
        "_require_safe_explorer_host(self.headers)" in do_get
        and do_get.index("_require_safe_explorer_host(self.headers)")
        < do_get.index("core.explorer_summary()"),
    )
    green(
        "Explorer Host parser is strict and loopback-only",
        "headers.get_all(\"Host\")" in guard_src
        and "len(values) != 1" in guard_src
        and "_ALLOWED_EXPLORER_HOSTS" in guard_src
        and explorer._ALLOWED_EXPLORER_HOSTS
        == {"127.0.0.1","localhost","::1"},
    )
    green(
        "Explorer Host hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-135 Explorer Host-header guard: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
