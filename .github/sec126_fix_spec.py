from pathlib import Path

root=Path(__file__).resolve().parents[1]
spec=root / "security_sec126_peer_config_resource_bounds_spec.py"
# The main patcher creates the spec in the workflow worktree.  Inspecting a
# decorated class method returns the decorator wrapper because _peer_locked does
# not use functools.wraps; read production core.py directly for the static
# wiring assertion instead.
text=spec.read_text(encoding="utf-8")
old='''    add_src=inspect.getsource(AxvenCore.add_outbound_peer)\n'''
new='''    core_src=(Path(__file__).resolve().parent / "core.py").read_text(encoding="utf-8")\n'''
if text.count(old) != 1:
    raise SystemExit("SEC-126 fixture anchor add_src not found exactly once")
text=text.replace(old,new,1)
text=text.replace('''        "len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS" in add_src\n        and add_src.index("len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS")\n            < add_src.index("self.outbound_peers.append(addr)"),\n''','''        "len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS" in core_src\n        and core_src.index("len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS")\n            < core_src.index("self.outbound_peers.append(addr)"),\n''',1)
spec.write_text(text,encoding="utf-8",newline="\n")
print("SEC-126 decorated source fixture fixed")
