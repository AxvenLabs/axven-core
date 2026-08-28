import hashlib
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
spec=root / "security_sec126_peer_config_resource_bounds_spec.py"
manifest_path=root / "release_manifest.json"
# The main patcher creates the spec in the workflow worktree. Inspecting a
# decorated class method returns the decorator wrapper because _peer_locked does
# not use functools.wraps; read production core.py directly for the static
# wiring assertion instead.
text=spec.read_text(encoding="utf-8")
old='''    add_src=inspect.getsource(AxvenCore.add_outbound_peer)\n'''
new='''    core_src=(Path(__file__).resolve().parent / "core.py").read_text(encoding="utf-8")\n'''
if text.count(old) != 1:
    raise SystemExit("SEC-126 fixture anchor add_src not found exactly once")
text=text.replace(old,new,1)
old_check='''        "len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS" in add_src\n        and add_src.index("len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS")\n            < add_src.index("self.outbound_peers.append(addr)"),\n'''
new_check='''        "len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS" in core_src\n        and core_src.index("len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS")\n            < core_src.index("self.outbound_peers.append(addr)"),\n'''
if text.count(old_check) != 1:
    raise SystemExit("SEC-126 fixture anchor source check not found exactly once")
text=text.replace(old_check,new_check,1)
spec.write_text(text,encoding="utf-8",newline="\n")

# The fixture correction changes the committed spec bytes, so refresh that
# release-manifest entry after the correction rather than leaving stale hashes.
raw=spec.read_bytes().replace(b"\r\n",b"\n")
spec.write_bytes(raw)
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["files"][spec.name]={
    "bytes":len(raw),
    "sha256":hashlib.sha256(raw).hexdigest(),
}
manifest_path.write_text(
    json.dumps(manifest,indent=2,sort_keys=True)+"\n",
    encoding="utf-8",
    newline="\n",
)
print("SEC-126 decorated source fixture and manifest fixed")
