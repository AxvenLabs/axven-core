#!/usr/bin/env python3
"""SEC-194: canonical outbound P2P status validation."""
from __future__ import annotations

from pathlib import Path
import axven
import p2p

def rejected(msg):
    try:
        p2p.validate_status_message(msg)
    except p2p.ProtocolError:
        return True
    return False

def main():
    checks=[]
    def green(name,condition=True):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    session=p2p.PeerSession(axven.Blockchain())
    canonical=session.status()
    green(
        "shared status validator accepts canonical status",
        p2p.validate_status_message(canonical) is canonical
        and session.handle(dict(canonical)) is None,
    )

    malformed=[]
    extra=dict(canonical); extra["extra"]=0; malformed.append(extra)
    for missing in ("height","tip_hash","chainwork"):
        bad=dict(canonical); bad.pop(missing); malformed.append(bad)
    wrong_type=dict(canonical); wrong_type["type"]="accepted"; malformed.append(wrong_type)
    green(
        "status envelope and type fail closed",
        rejected(None) and all(rejected(item) for item in malformed),
    )
    green(
        "status height uses exact non-negative integer domain",
        all(rejected({**canonical,"height":v}) for v in (True,-1,"0",0.0,None)),
    )
    green(
        "status chainwork uses exact non-negative integer domain",
        all(rejected({**canonical,"chainwork":v}) for v in (True,-1,"1",1.0,None)),
    )
    green(
        "status tip hash remains canonical lowercase hex",
        all(
            rejected({**canonical,"tip_hash":v})
            for v in (None,0,"0"*63,"0"*65,"g"*64,"A"*64)
        ),
    )

    original_request=p2p.request
    calls=[]
    marker=object()
    def fake_request(sock,msg,deadline=None):
        calls.append((sock,msg,deadline))
        return dict(canonical)
    p2p.request=fake_request
    try:
        result=p2p.request_status(marker,deadline=123.0)
    finally:
        p2p.request=original_request
    green(
        "outbound status helper sends exact get_status and validates reply",
        result==canonical and calls==[(marker,{"type":"get_status"},123.0)],
    )

    p2p.request=lambda *args,**kwargs:{**canonical,"height":True}
    try:
        outbound_bad=False
        try:p2p.request_status(marker)
        except p2p.ProtocolError:outbound_bad=True
    finally:
        p2p.request=original_request
    green("outbound status helper rejects malformed remote reply",outbound_bad)

    peer_probe=Path("tools/peer_probe.py").read_text(encoding="utf-8")
    acceptance=Path("tools/public_peer_acceptance.py").read_text(encoding="utf-8")
    seed_health=Path("tools/seed_health.py").read_text(encoding="utf-8")
    green(
        "operator probes use shared outbound status validator",
        "status=p2p.request_status(sock)" in peer_probe
        and "reply=p2p.request_status(s)" in acceptance
        and "status=p2p.request_status(sock)" in seed_health
        and 'p2p.request(sock,{"type":"get_status"})' not in peer_probe
        and 'p2p.request(s,{"type":"get_status"})' not in acceptance
        and 'p2p.request(sock,{"type":"get_status"})' not in seed_health,
    )

    source=Path(p2p.__file__).read_text(encoding="utf-8")
    green(
        "inbound SEC-113 and outbound status share one validator",
        'def validate_status_message(' in source
        and 'validate_status_message(msg)' in source
        and 'def request_status(' in source,
    )
    green(
        "SEC-194 leaves chain identity and PQ activation semantics unchanged",
        axven.CHAIN_ID=="axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        =="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"]==2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"]==5000
        and axven.Blockchain().tip.hash()
        =="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )
    assert len(checks)==10
    print("SEC-194 outbound status validation: 10/10 GREEN")

if __name__=="__main__":main()
