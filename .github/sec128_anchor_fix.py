#!/usr/bin/env python3
from pathlib import Path

p = Path('.github/sec128_apply.py')
s = p.read_text(encoding='utf-8')
old = '''rpc = replace_once(\n    rpc,\n    b"        budget = [4096]\\n",\n    b"        budget = [MAX_RPC_PARAM_NODES]\\n",\n    "validate-param default budget",\n)\nrpc = replace_once(\n    rpc,\n    b"            budget = [4096]\\n",\n    b"            budget = [MAX_RPC_PARAM_NODES]\\n",\n    "dispatcher param budget",\n)'''
new = '''rpc = replace_once(\n    rpc,\n    b"def _validate_param_depth(value, depth=0, budget=None):\\n    if budget is None:\\n        budget = [4096]\\n",\n    b"def _validate_param_depth(value, depth=0, budget=None):\\n    if budget is None:\\n        budget = [MAX_RPC_PARAM_NODES]\\n",\n    "validate-param default budget",\n)\nrpc = replace_once(\n    rpc,\n    b"                    raise RPCError(\\\"invalid param key\\\")\\n            budget = [4096]\\n            for value in params.values():\\n",\n    b"                    raise RPCError(\\\"invalid param key\\\")\\n            budget = [MAX_RPC_PARAM_NODES]\\n            for value in params.values():\\n",\n    "dispatcher param budget",\n)'''
if s.count(old) != 1:
    raise RuntimeError(f'expected one applicator anchor block, found {s.count(old)}')
p.write_text(s.replace(old, new, 1), encoding='utf-8', newline='\n')
print('SEC-128 applicator anchors repaired')
