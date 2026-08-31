from __future__ import annotations

import hashlib
import json
from pathlib import Path

spec = Path("security_sec208_release_tag_provenance_spec.py")
text = spec.read_text(encoding="utf-8")
old = '''    normalized_notes = " ".join(notes.split())
    normalized_checklist = " ".join(checklist.split())
    assert "v0.9.0-devnet" in notes and "MUST NOT be reused or moved" in normalized_notes
    assert "release commit SHA: <PASTE FINAL 40-HEX COMMIT SHA HERE>" in notes
    assert "release_manifest.json SHA-256: <PASTE FINAL 64-HEX SHA-256 HERE>" in notes
    assert "release_provenance.py prepare" in notes
    assert "release_provenance.py verify" in notes
    assert "without --force" in normalized_notes
    assert "v0.9.0-devnet" in checklist and "never reuse or move" in normalized_checklist
'''
new = '''    normalized_notes = " ".join(notes.split())
    normalized_checklist = " ".join(checklist.split())
    plain_notes = normalized_notes.replace("`", "")
    plain_checklist = normalized_checklist.replace("`", "")
    assert "v0.9.0-devnet" in notes and "MUST NOT be reused or moved" in normalized_notes
    assert "release commit SHA: <PASTE FINAL 40-HEX COMMIT SHA HERE>" in notes
    assert "release_manifest.json SHA-256: <PASTE FINAL 64-HEX SHA-256 HERE>" in notes
    assert "release_provenance.py prepare" in notes
    assert "release_provenance.py verify" in notes
    assert "without --force" in plain_notes
    assert "v0.9.0-devnet" in checklist and "never reuse or move" in plain_checklist
'''
if text.count(old) != 1:
    raise SystemExit("SEC-208 markdown assertion anchor missing or ambiguous")
text = text.replace(old, new)
count_old = '    assert checks == 11, checks\n    print("SEC-208 release tag provenance: 11/11 GREEN")'
count_new = '    assert checks == 12, checks\n    print("SEC-208 release tag provenance: 12/12 GREEN")'
if text.count(count_old) != 1:
    raise SystemExit("SEC-208 count anchor missing or ambiguous")
text = text.replace(count_old, count_new)
spec.write_text(text, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
data = spec.read_bytes()
manifest["files"][spec.as_posix()] = {
    "bytes": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
}
manifest["files"] = dict(sorted(manifest["files"].items()))
manifest_path.write_text(
    json.dumps(manifest, indent=2) + "\n",
    encoding="utf-8",
    newline="\n",
)
