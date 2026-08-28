#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

core_path = Path("core.py")
source = core_path.read_text(encoding="utf-8")
old = '''    @staticmethod
    def _validate_peer_retry_seconds(value):
        if isinstance(value,bool) or not isinstance(value,(int,float)):
            raise ValueError("invalid peer retry timing")
        raw=float(value)
        if (
            not math.isfinite(raw)
            or raw < 0.0
            or raw > 3600.0
        ):
            raise ValueError("invalid peer retry timing")
        return raw
'''
new = '''    @staticmethod
    def _validate_peer_retry_seconds(value):
        if isinstance(value,bool) or not isinstance(value,(int,float)):
            raise ValueError("invalid peer retry timing")
        # Compare in the original numeric domain before float conversion so
        # arbitrarily large Python integers fail closed without OverflowError.
        if value < 0 or value > 3600:
            raise ValueError("invalid peer retry timing")
        raw=float(value)
        if not math.isfinite(raw):
            raise ValueError("invalid peer retry timing")
        return raw
'''
if source.count(old) != 1:
    raise SystemExit("SEC-104 retry-seconds target mismatch")
core_path.write_text(source.replace(old, new), encoding="utf-8", newline="\n")

spec_path = Path("security_sec104_peer_retry_delay_domain_spec.py")
spec = spec_path.read_text(encoding="utf-8")
old_cases = '''        (lambda: core.peer_retry_delay(peer,True,60.0), "boolean retry timing rejected"),
        (lambda: core.peer_retry_delay(peer,"5",60.0), "string retry timing rejected"),
'''
new_cases = '''        (lambda: core.peer_retry_delay(peer,True,60.0), "boolean retry timing rejected"),
        (lambda: core.peer_retry_delay(peer,"5",60.0), "string retry timing rejected"),
        (lambda: core.set_peer_retry_schedule(peer,10**1000,5.0), "extreme integer retry delay rejected"),
        (lambda: core.peer_retry_delay(peer,10**1000,60.0), "extreme integer retry base rejected"),
        (lambda: core.peer_retry_delay(peer,5.0,10**1000), "extreme integer retry cap rejected"),
'''
if spec.count(old_cases) != 1:
    raise SystemExit("SEC-104 spec target mismatch")
spec_path.write_text(spec.replace(old_cases, new_cases), encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("core.py", spec_path.name):
    data = Path(name).read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest["files"] = dict(sorted(manifest["files"].items()))
manifest_path.write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
    newline="\n",
)
