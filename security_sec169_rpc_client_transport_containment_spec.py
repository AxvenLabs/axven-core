#!/usr/bin/env python3
"""SEC-169 authenticated RPC transport-containment regression contract."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import axven
import axven_cli
import axven_console
import canonical_ops

TOKEN="34"*32


def start_server(handler):
    server=ThreadingHTTPServer(("127.0.0.1",0),handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    return server,thread


def stop_server(server,thread):
    server.shutdown()
    server.server_close()
    thread.join(2.0)


def json_reply(handler,status,obj,extra_headers=None):
    raw=json.dumps(obj,separators=(",",":")).encode()
    handler.send_response(status)
    for key,value in (extra_headers or {}).items():
        handler.send_header(key,value)
    handler.send_header("Content-Type","application/json")
    handler.send_header("Content-Length",str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def main():
    checks=[]
    def green(name,condition):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    ambient_proxy_discovery=[]
    original_getproxies=axven_cli.urllib.request.getproxies
    def forbidden_getproxies():
        ambient_proxy_discovery.append(True)
        raise AssertionError("ambient proxy discovery executed")
    axven_cli.urllib.request.getproxies=forbidden_getproxies
    try:
        opener=axven_cli._build_rpc_opener()
    finally:
        axven_cli.urllib.request.getproxies=original_getproxies
    redirects=[h for h in opener.handlers if isinstance(h,axven_cli.urllib.request.HTTPRedirectHandler)]
    green(
        "RPC opener suppresses ambient proxy discovery",
        ambient_proxy_discovery==[],
    )
    green(
        "RPC opener replaces default redirect handling with fail-closed handler",
        len(redirects)==1 and isinstance(redirects[0],axven_cli._RejectRPCRedirects),
    )

    # Ambient HTTP_PROXY must never observe a bearer-authenticated loopback call.
    target_seen=[]
    proxy_seen=[]
    class Target(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            n=int(self.headers.get("Content-Length","0")); self.rfile.read(n)
            target_seen.append(self.headers.get("Authorization"))
            json_reply(self,200,{"ok":True,"result":{"height":0}})
    class Proxy(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            n=int(self.headers.get("Content-Length","0")); self.rfile.read(n)
            proxy_seen.append(self.headers.get("Authorization"))
            json_reply(self,200,{"ok":False,"error":"proxy observed request"})
    target,target_thread=start_server(Target)
    proxy,proxy_thread=start_server(Proxy)
    old_env={key:os.environ.get(key) for key in ("http_proxy","HTTP_PROXY","no_proxy","NO_PROXY")}
    try:
        proxy_url=f"http://127.0.0.1:{proxy.server_address[1]}"
        os.environ["http_proxy"]=proxy_url
        os.environ["HTTP_PROXY"]=proxy_url
        os.environ["no_proxy"]=""
        os.environ["NO_PROXY"]=""
        result=axven_cli.call("127.0.0.1",target.server_address[1],"get_status",{},auth_token=TOKEN)
    finally:
        for key,value in old_env.items():
            if value is None: os.environ.pop(key,None)
            else: os.environ[key]=value
        stop_server(proxy,proxy_thread)
        stop_server(target,target_thread)
    green(
        "authenticated RPC ignores ambient HTTP proxy configuration",
        result.get("ok") is True and target_seen==["Bearer "+TOKEN] and proxy_seen==[],
    )

    # A loopback endpoint cannot redirect the Authorization header elsewhere.
    redirected_seen=[]
    redirect_origin_seen=[]
    class Capture(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def _capture(self):
            redirected_seen.append(self.headers.get("Authorization"))
            json_reply(self,200,{"ok":True})
        do_GET=_capture
        do_POST=_capture
    capture,capture_thread=start_server(Capture)
    capture_url=f"http://127.0.0.1:{capture.server_address[1]}/stolen"
    class RedirectOrigin(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            n=int(self.headers.get("Content-Length","0")); self.rfile.read(n)
            redirect_origin_seen.append(self.headers.get("Authorization"))
            json_reply(self,302,{"ok":False,"error":"redirect"},{"Location":capture_url})
    origin,origin_thread=start_server(RedirectOrigin)
    try:
        redirected=axven_cli.call("127.0.0.1",origin.server_address[1],"get_status",{},auth_token=TOKEN)
    finally:
        stop_server(origin,origin_thread)
        stop_server(capture,capture_thread)
    green(
        "authenticated RPC rejects redirects before bearer forwarding",
        redirected.get("ok") is False
        and "redirect" in redirected.get("error","").lower()
        and redirect_origin_seen==["Bearer "+TOKEN]
        and redirected_seen==[],
    )

    import inspect
    cli_src=inspect.getsource(axven_cli.call)
    ops_src=inspect.getsource(canonical_ops.rpc)
    green(
        "CLI routes RPC through contained opener",
        "open_rpc_request(" in cli_src and "urllib.request.urlopen(" not in cli_src,
    )
    green(
        "canonical operator helper routes RPC through contained opener",
        "open_rpc_request(" in ops_src and "urllib.request.urlopen(" not in ops_src
        and "Authorization" in ops_src and "Bearer " in ops_src,
    )
    green(
        "interactive console inherits contained CLI transport",
        axven_console.call is axven_cli.call,
    )
    green(
        "RPC transport containment leaves canonical chain identity unchanged",
        axven.CHAIN_ID=="axven-devnet-2"
        and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )
    print(f"SEC-169 RPC client transport containment: {len(checks)}/{len(checks)} GREEN")

if __name__=="__main__":
    main()
