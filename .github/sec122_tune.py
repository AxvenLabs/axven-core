#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[1]
p=ROOT/"p2p.py"
text=p.read_bytes().decode("utf-8").replace("\r\n","\n")
old=(
    "INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_RATE = 4.0\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_BURST = 8\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_RATE = 1.0\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_BURST = 4\n"
)
new=(
    "INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_RATE = 4.0\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_BURST = 16\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_RATE = 1.0\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_BURST = 8\n"
)
if text.count(old) != 1:
    raise SystemExit("SEC-122 tune anchor mismatch")
text=text.replace(old,new,1)
p.write_bytes(text.encode("utf-8"))

manifest_path=ROOT/"release_manifest.json"
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
data=p.read_bytes()
manifest["files"]["p2p.py"]={
    "bytes":len(data),
    "sha256":hashlib.sha256(data).hexdigest(),
}
manifest_path.write_bytes((json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8"))
print("SEC-122 healthy-sync burst tuned")
