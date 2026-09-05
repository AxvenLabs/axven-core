#!/usr/bin/env python3
"""RUST-149 TEST-ONLY monitor rotation journal/checkpoint producer."""
from __future__ import annotations
import base64, copy, hashlib, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_146_rust145_checkpoint_monitor_verify as monitor_verify
import rust_147_rust146_checkpoint_monitor_rotation_verify as rotation1_verify
import rust_148_multistep_rust146_checkpoint_monitor_rotation_verify as rotation2_verify
import rust_149_rust146_checkpoint_monitor_rotation_journal_verify as journal_verify
OUT=Path('/tmp')
SEEDS={monitor_verify.MONITOR_2_ID:'6f'*32,monitor_verify.MONITOR_3_ID:'7f'*32,rotation1_verify.M4_ID:'8f'*32,rotation2_verify.M5_ID:'9f'*32}
def private_for(mid,pins):
    p=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[mid])); pub=p.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    if pub!=pins[mid]: raise AssertionError('RUST-149 TEST-only journal monitor public-key pin mismatch')
    return p
def sign_rows(statement,journal_raw,pins):
    msg=journal_verify.checkpoint_message(statement,journal_raw)
    return [{'monitor_id':mid,'signature':base64.b64encode(private_for(mid,pins).sign(msg)).decode('ascii')} for mid in sorted(pins)]
def checkpoint(statement,journal_raw,pins): return {'schema':journal_verify.CHECKPOINT_SCHEMA,'algorithm':journal_verify.ALGORITHM,'threshold':journal_verify.THRESHOLD,'statement':statement,'monitors':sign_rows(statement,journal_raw,pins),'production':False}
def main():
    if len(sys.argv)!=2 or len(sys.argv[1])!=40 or any(c not in '0123456789abcdef' for c in sys.argv[1]): raise SystemExit('usage: rust_149_rust146_checkpoint_monitor_rotation_journal_fixture.py SOURCE_SHA')
    source_sha=sys.argv[1]
    mraw,m=floor_verify.load_canonical(OUT/'axven-rust145-final-monitor-rotation-checkpoint.json','RUST-145 final monitor rotation checkpoint'); target=monitor_verify.checkpoint_target(mraw,m['statement'])
    if target['activation_source_commit']!=source_sha: raise AssertionError('RUST-149 target source mismatch')
    paths=['axven-rust146-monitor-bundle.json','axven-rust147-monitor-set-rotation.json','axven-rust147-monitor-set-rotation-auth.json','axven-rust147-successor-monitor-bundle.json','axven-rust148-second-monitor-set-rotation.json','axven-rust148-second-monitor-set-rotation-auth.json','axven-rust148-final-monitor-bundle.json']
    raws=[floor_verify.load_canonical(OUT/p,'RUST-149 predecessor evidence')[0] for p in paths]; entries=journal_verify.expected_entries(*raws)
    pj=journal_verify.expected_journal(entries[:2],source_sha,target); pjr=material_verify.canonical(pj); ps=journal_verify.checkpoint_statement(pjr,material_verify.canonical(entries[1]),1,rotation1_verify.new_monitor_set(),None,2,target,source_sha); pc=checkpoint(ps,pjr,rotation1_verify.NEW_PINNED_MONITORS); pcr=material_verify.canonical(pc)
    fj=journal_verify.expected_journal(entries,source_sha,target); fjr=material_verify.canonical(fj); fs=journal_verify.checkpoint_statement(fjr,material_verify.canonical(entries[2]),2,rotation2_verify.final_monitor_set(),hashlib.sha256(pcr).hexdigest(),3,target,source_sha); fc=checkpoint(fs,fjr,rotation2_verify.FINAL_PINNED_MONITORS)
    fork=copy.deepcopy(fs); fork['journal_sha256']='f'*64; fork['head_entry_sha256']='e'*64; fkc=checkpoint(fork,fjr,rotation2_verify.FINAL_PINNED_MONITORS)
    for name,raw in [('prefix-monitor-rotation-journal',pjr),('prefix-monitor-rotation-checkpoint',pcr),('final-monitor-rotation-journal',fjr),('final-monitor-rotation-checkpoint',material_verify.canonical(fc)),('observed-fork-monitor-rotation-checkpoint',material_verify.canonical(fkc))]: (OUT/f'axven-rust149-{name}.json').write_bytes(raw)
    print('RUST-149 TEST-only monitor rotation journal/checkpoint fixture: GREEN')
if __name__=='__main__': main()
