#!/usr/bin/env python3
from pathlib import Path
R=Path(__file__).resolve().parent
checks=[]
def ok(n,x): assert x,n; checks.append(n)
for p in [
 ".github/CODEOWNERS",
 ".github/PULL_REQUEST_TEMPLATE.md",
 ".github/ISSUE_TEMPLATE/bug_report.yml",
 ".github/ISSUE_TEMPLATE/feature_request.yml",
 ".github/ISSUE_TEMPLATE/config.yml",
 ".github/release.yml",
 "tools/peer_probe.py",
 "tools/public_peer_acceptance.py",
 "docs/BRANCH_PROTECTION.md",
 "docs/PUBLIC_DEVNET_HARDENING.md",
 "docs/RELEASE_HARDENING.md",
]:
    ok(p,(R/p).is_file())
txt=(R/"docs/PUBLIC_DEVNET_HARDENING.md").read_text(encoding="utf-8")
ok("no RPC exposure","Do not forward the RPC" in txt)
ok("manual exposure","does not open ports" in txt)
print(f"Checkpoint 28 spec: {len(checks)}/{len(checks)} GREEN")
