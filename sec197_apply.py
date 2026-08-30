#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one replacement in {path.name}, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


core = ROOT / "core.py"
replace_once(
    core,
    "from typing import Optional, Tuple\nimport math\nimport threading\n",
    "from typing import Optional, Tuple\nimport ipaddress\nimport math\nimport threading\n",
)
replace_once(
    core,
    "    MAX_CONFIGURED_PEERS = 256\n    PEER_HEALTH_INCIDENT_HISTORY_LIMIT = 64\n",
    "    MAX_CONFIGURED_PEERS = 256\n    # SEC-197: one routable IP network group or canonical DNS host must not\n"
    "    # occupy an arbitrary fraction of the configured outbound set.  This\n"
    "    # is local peering policy only; loopback remains exempt for devnet labs.\n"
    "    MAX_CONFIGURED_PEERS_PER_DIVERSITY_GROUP = 4\n"
    "    PEER_DIVERSITY_IPV4_PREFIX = 24\n"
    "    PEER_DIVERSITY_IPV6_PREFIX = 48\n"
    "    PEER_HEALTH_INCIDENT_HISTORY_LIMIT = 64\n",
)
insert_anchor = """        if len(host) > 255:\n            raise ValueError(\"peer host too long\")\n        return (host,port)\n\n    @staticmethod\n    def _peer_health_timestamp():\n"""
insert_replacement = """        if len(host) > 255:\n            raise ValueError(\"peer host too long\")\n        return (host,port)\n\n    @staticmethod\n    def _peer_diversity_group(host):\n        \"\"\"Return a stable Sybil/eclipsing group for one configured host.\"\"\"\n        if type(host) is not str:\n            raise ValueError(\"peer host must be string\")\n        normalized=host.strip().casefold()\n        while normalized.endswith(\".\"):\n            normalized=normalized[:-1]\n        if not normalized:\n            raise ValueError(\"peer host required\")\n\n        ip_text=normalized\n        if ip_text.startswith(\"[\") and ip_text.endswith(\"]\"):\n            ip_text=ip_text[1:-1]\n        try:\n            ip=ipaddress.ip_address(ip_text)\n        except ValueError:\n            # The existing peer parser deliberately permits non-ASCII host\n            # tokens.  Do not invent IDNA canonicalization in this SEC; ASCII\n            # DNS names are grouped case/trailing-dot insensitively.\n            if not normalized.isascii():\n                return None\n            if normalized == \"localhost\" or normalized.endswith(\".localhost\"):\n                return None\n            return (\"dns\",normalized)\n\n        # Local loopback/link-local test fabrics are intentionally exempt;\n        # private/ULA/public unicast addresses still receive prefix grouping.\n        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:\n            return None\n        prefix=(\n            AxvenCore.PEER_DIVERSITY_IPV4_PREFIX\n            if ip.version == 4\n            else AxvenCore.PEER_DIVERSITY_IPV6_PREFIX\n        )\n        network=ipaddress.ip_network((ip,prefix),strict=False)\n        return (f\"ipv{ip.version}\",network.with_prefixlen)\n\n    @classmethod\n    def _validate_peer_diversity(cls, peers):\n        \"\"\"Normalize peers and fail closed when one network group dominates.\"\"\"\n        normalized=[]\n        seen=set()\n        groups={}\n        for peer in peers:\n            addr=cls._parse_peer(peer)\n            normalized.append(addr)\n            if addr in seen:\n                continue\n            seen.add(addr)\n            group=cls._peer_diversity_group(addr[0])\n            if group is None:\n                continue\n            count=groups.get(group,0)+1\n            if count > cls.MAX_CONFIGURED_PEERS_PER_DIVERSITY_GROUP:\n                raise ValueError(\"configured peer diversity limit exceeded\")\n            groups[group]=count\n        return normalized\n\n    @staticmethod\n    def _peer_health_timestamp():\n"""
replace_once(core, insert_anchor, insert_replacement)
replace_once(
    core,
    """        if addr not in self.outbound_peers:\n            if len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS:\n                raise ValueError(\"configured peer limit exceeded\")\n            self.outbound_peers.append(addr)\n""",
    """        if addr not in self.outbound_peers:\n            if len(self.outbound_peers) >= self.MAX_CONFIGURED_PEERS:\n                raise ValueError(\"configured peer limit exceeded\")\n            # Reject a fifth distinct endpoint from the same routable prefix\n            # or canonical DNS host before mutating memory or persistence.\n            self._validate_peer_diversity([*self.outbound_peers,addr])\n            self.outbound_peers.append(addr)\n""",
)

datadir = ROOT / "datadir.py"
replace_once(
    datadir,
    """            peers.append(AxvenCore._parse_peer(peer))\n        return peers\n\n    def save_peers(self,peers):\n""",
    """            peers.append(AxvenCore._parse_peer(peer))\n        return AxvenCore._validate_peer_diversity(peers)\n\n    def save_peers(self,peers):\n""",
)
replace_once(
    datadir,
    """            host,port=AxvenCore._parse_peer(peer)\n            normalized.append({\"host\":host,\"port\":port})\n        payload=(json.dumps(normalized,indent=2,sort_keys=True)+\"\\n\").encode(\"utf-8\")\n""",
    """            host,port=AxvenCore._parse_peer(peer)\n            normalized.append((host,port))\n        normalized=AxvenCore._validate_peer_diversity(normalized)\n        payload=(json.dumps(\n            [{\"host\":host,\"port\":port} for host,port in normalized],\n            indent=2,sort_keys=True,\n        )+\"\\n\").encode(\"utf-8\")\n""",
)

spec = ROOT / "security_sec197_peer_diversity_spec.py"
spec.write_text(r'''#!/usr/bin/env python3
"""SEC-197: bound configured outbound peer eclipse/Sybil concentration."""

from __future__ import annotations

import inspect
import json
import os
import tempfile

import axven
from core import AxvenCore
from datadir import DataDir


def expect_value_error(fn, contains):
    try:
        fn()
    except ValueError as exc:
        assert contains in str(exc), str(exc)
        return True
    return False


def main():
    checks=[]
    def green(label, condition):
        assert condition, label
        checks.append(label)
        print("[GREEN]", label)

    green(
        "peer diversity policy constants pinned",
        AxvenCore.MAX_CONFIGURED_PEERS_PER_DIVERSITY_GROUP == 4
        and AxvenCore.PEER_DIVERSITY_IPV4_PREFIX == 24
        and AxvenCore.PEER_DIVERSITY_IPV6_PREFIX == 48,
    )
    green(
        "IPv4 routable peers are grouped by /24",
        AxvenCore._peer_diversity_group("8.8.8.1") == ("ipv4","8.8.8.0/24")
        and AxvenCore._peer_diversity_group("8.8.8.254") == ("ipv4","8.8.8.0/24")
        and AxvenCore._peer_diversity_group("8.8.9.1") == ("ipv4","8.8.9.0/24"),
    )
    green(
        "IPv6 routable peers are grouped by /48",
        AxvenCore._peer_diversity_group("2606:4700:4700::1")
            == ("ipv6","2606:4700:4700::/48")
        and AxvenCore._peer_diversity_group("2606:4700:4701::1")
            == ("ipv6","2606:4700:4701::/48"),
    )
    green(
        "DNS aliases share a canonical diversity group",
        AxvenCore._peer_diversity_group("Seed.Example.Org.")
            == ("dns","seed.example.org")
        and AxvenCore._peer_diversity_group("seed.example.org")
            == ("dns","seed.example.org"),
    )
    green(
        "loopback remains exempt for multi-node local devnet labs",
        AxvenCore._peer_diversity_group("127.0.0.1") is None
        and AxvenCore._peer_diversity_group("::1") is None
        and AxvenCore._peer_diversity_group("localhost") is None,
    )

    core=AxvenCore()
    for i,host in enumerate(("8.8.8.1","8.8.8.2","8.8.8.3","8.8.8.4")):
        core.add_outbound_peer((host,20000+i))
    before=list(core.outbound_peers)
    persisted=[]
    core.peer_persist_callback=lambda peers: persisted.append(list(peers))
    green(
        "fifth IPv4 endpoint in one /24 is rejected atomically",
        expect_value_error(
            lambda: core.add_outbound_peer(("8.8.8.5",20005)),
            "configured peer diversity limit exceeded",
        )
        and core.outbound_peers == before
        and not persisted,
    )
    green(
        "a distinct IPv4 /24 remains admissible after a group fills",
        core.add_outbound_peer(("8.8.9.1",20006)) == ("8.8.9.1",20006)
        and len(core.outbound_peers) == 5
        and len(persisted) == 1,
    )

    dns=AxvenCore()
    dns_hosts=("Seed.Example.Org","seed.example.org.","SEED.EXAMPLE.ORG","seed.example.org")
    for i,host in enumerate(dns_hosts):
        dns.add_outbound_peer((host,21000+i))
    dns_before=list(dns.outbound_peers)
    green(
        "case and trailing-dot DNS aliases cannot mint extra Sybil slots",
        expect_value_error(
            lambda: dns.add_outbound_peer(("SeEd.ExAmPlE.OrG.",21010)),
            "configured peer diversity limit exceeded",
        )
        and dns.outbound_peers == dns_before,
    )

    v6=AxvenCore()
    for i in range(1,5):
        v6.add_outbound_peer((f"2606:4700:4700::{i}",22000+i))
    green(
        "fifth IPv6 endpoint in one /48 is rejected while another /48 is allowed",
        expect_value_error(
            lambda: v6.add_outbound_peer(("2606:4700:4700::5",22005)),
            "configured peer diversity limit exceeded",
        )
        and v6.add_outbound_peer(("2606:4700:4701::1",22006))
            == ("2606:4700:4701::1",22006),
    )

    local=AxvenCore()
    for i in range(12):
        local.add_outbound_peer(("127.0.0.1",23000+i))
    green(
        "local multi-port devnet topology remains compatible",
        len(local.outbound_peers) == 12,
    )

    bad=[(f"8.8.8.{i}",24000+i) for i in range(1,6)]
    with tempfile.TemporaryDirectory() as td:
        dd=DataDir(td)
        green(
            "peer writer refuses to persist an eclipse-concentrated set",
            expect_value_error(
                lambda: dd.save_peers(bad),
                "configured peer diversity limit exceeded",
            )
            and not dd.peer_file.exists(),
        )

        dd.peer_file.write_text(
            json.dumps([{"host":host,"port":port} for host,port in bad]),
            encoding="utf-8",
        )
        if os.name == "posix":
            os.chmod(dd.peer_file,0o600)
        green(
            "persisted eclipse-concentrated peer sets fail closed on read",
            expect_value_error(
                dd.load_peers,
                "configured peer diversity limit exceeded",
            ),
        )

        good=[("8.8.8.1",25001),("8.8.9.1",25002),("1.1.1.1",25003)]
        dd.save_peers(good)
        green(
            "diverse persisted peer sets still round-trip canonically",
            dd.load_peers() == good,
        )

    add_src=inspect.getsource(AxvenCore.add_outbound_peer)
    save_src=inspect.getsource(DataDir.save_peers)
    load_src=inspect.getsource(DataDir.load_peers)
    green(
        "diversity gates precede runtime mutation and persistence publication",
        "_validate_peer_diversity([*self.outbound_peers,addr])" in add_src
        and add_src.index("_validate_peer_diversity([*self.outbound_peers,addr])")
            < add_src.index("self.outbound_peers.append(addr)")
        and "_validate_peer_diversity(normalized)" in save_src
        and "return AxvenCore._validate_peer_diversity(peers)" in load_src,
    )

    green(
        "peer diversity hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks) == 14, len(checks)
    print("SEC-197 peer diversity: 14/14 GREEN")


if __name__ == "__main__":
    main()
''', encoding="utf-8", newline="\n")

# Remove the write-capable one-shot machinery from the final tree before
# manifest generation; the final PR must contain only production/test pins.
for rel in ("sec197_apply.py", ".github/workflows/sec197_apply.yml"):
    path = ROOT / rel
    if path.exists():
        path.unlink()

manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for rel in ("core.py", "datadir.py", "security_sec197_peer_diversity_spec.py"):
    data = (ROOT / rel).read_bytes()
    manifest["files"][rel] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)

print("SEC-197 one-shot apply complete")
