#!/usr/bin/env python3
"""SEC-164 bounded RPC-client response regression contract."""
import inspect
import axven,axven_cli,axven_console,canonical_ops

class FakeStream:
    def __init__(self,payload): self.payload=payload; self.read_sizes=[]
    def read(self,n=-1): self.read_sizes.append(n); return self.payload if n<0 else self.payload[:n]

def main():
    checks=[]
    def green(name,cond): assert cond,name; checks.append(name); print(f"[GREEN] {name}")
    max_block_bytes=axven.CHAIN_CONFIG["max_block_bytes"]
    green("RPC client response budget is finite and above maximum block size",type(axven_cli.MAX_RPC_RESPONSE_BYTES) is int and axven_cli.MAX_RPC_RESPONSE_BYTES>=2*max_block_bytes and axven_cli.MAX_RPC_RESPONSE_BYTES<=32*1024*1024)
    original=axven_cli.MAX_RPC_RESPONSE_BYTES
    try:
        axven_cli.MAX_RPC_RESPONSE_BYTES=64
        good=FakeStream(b'{"ok":true,"result":{"height":0}}')
        parsed=axven_cli.read_rpc_json_response(good)
        green("healthy RPC response is read with cap plus one",parsed["ok"] is True and good.read_sizes==[65])
        oversized=FakeStream(b'x'*65)
        loads_called=[]; old_loads=axven_cli.json.loads
        try:
            axven_cli.json.loads=lambda raw: loads_called.append(True) or old_loads(raw)
            try: axven_cli.read_rpc_json_response(oversized)
            except axven_cli.RPCClientError as exc: rejected=str(exc)=="RPC response too large"
            else: rejected=False
        finally: axven_cli.json.loads=old_loads
        green("oversized RPC response is rejected before JSON parser",rejected and loads_called==[] and oversized.read_sizes==[65])
        invalid=FakeStream(b'not-json')
        try: axven_cli.read_rpc_json_response(invalid)
        except axven_cli.RPCClientError as exc: invalid_rejected=str(exc)=="invalid RPC response"
        else: invalid_rejected=False
        green("malformed bounded RPC response fails closed",invalid_rejected)
        scalar=FakeStream(b'[]')
        try: axven_cli.read_rpc_json_response(scalar)
        except axven_cli.RPCClientError as exc: scalar_rejected=str(exc)=="RPC response must be object"
        else: scalar_rejected=False
        green("RPC response top level must be object",scalar_rejected)
    finally: axven_cli.MAX_RPC_RESPONSE_BYTES=original
    cli_src=inspect.getsource(axven_cli.call)
    green("CLI success and HTTP-error paths use bounded reader",cli_src.count("read_rpc_json_response(")>=2 and ".read()" not in cli_src)
    ops_src=inspect.getsource(canonical_ops.rpc)
    green("canonical operator client uses the same bounded reader",ops_src.count("read_rpc_json_response(")>=2 and ".read()" not in ops_src)
    green("interactive console inherits hardened CLI call",axven_console.call is axven_cli.call)
    green("SEC-164 leaves canonical identity unchanged",axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    print(f"SEC-164 RPC client response budget: {len(checks)}/{len(checks)} GREEN")
if __name__=='__main__': main()
