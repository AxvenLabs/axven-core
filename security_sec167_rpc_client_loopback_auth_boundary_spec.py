#!/usr/bin/env python3
"""SEC-167 authenticated RPC client target-boundary regression contract."""
import axven
import axven_cli

TOKEN="11"*32

def main():
    checks=[]
    def green(name,condition):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    green("authenticated IPv4 loopback target accepted",
          axven_cli._rpc_client_url("127.0.0.1",18443,TOKEN)=="http://127.0.0.1:18443/")
    green("authenticated localhost target accepted",
          axven_cli._rpc_client_url("localhost",18443,TOKEN)=="http://localhost:18443/")
    green("authenticated IPv6 loopback target is bracketed",
          axven_cli._rpc_client_url("::1",18443,TOKEN)=="http://[::1]:18443/")

    for host in ("198.51.100.7","example.invalid","127.0.0.1@evil.invalid","127.0.0.1/evil"):
        try:
            axven_cli._rpc_client_url(host,18443,TOKEN)
        except axven_cli.RPCClientError:
            pass
        else:
            raise AssertionError(f"authenticated non-loopback target accepted: {host}")
    green("authenticated remote and authority-injection targets rejected",True)

    calls=[]
    original=axven_cli.urllib.request.urlopen
    try:
        def forbidden(*args,**kwargs):
            calls.append((args,kwargs))
            raise AssertionError("network must not be touched")
        axven_cli.urllib.request.urlopen=forbidden
        result=axven_cli.call("198.51.100.7",18443,"get_status",{},auth_token=TOKEN)
    finally:
        axven_cli.urllib.request.urlopen=original
    green("token exfiltration is rejected before network I/O",
          result.get("ok") is False and "loopback" in result.get("error","") and calls==[])

    green("tokenless explicit remote target remains available for legacy test use",
          axven_cli._rpc_client_url("198.51.100.7",18443,None)=="http://198.51.100.7:18443/")

    for port in (0,65536,True,"18443"):
        try:
            axven_cli._rpc_client_url("127.0.0.1",port,TOKEN)
        except axven_cli.RPCClientError:
            pass
        else:
            raise AssertionError(f"invalid RPC port accepted: {port!r}")
    green("authenticated client rejects port coercion aliases and out-of-range values",True)

    green("RPC client hardening leaves canonical chain identity unchanged",
          axven.CHAIN_ID=="axven-devnet-2"
          and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
          and axven.Blockchain().tip.hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
    print(f"SEC-167 RPC client loopback auth boundary: {len(checks)}/{len(checks)} GREEN")

if __name__=="__main__": main()
