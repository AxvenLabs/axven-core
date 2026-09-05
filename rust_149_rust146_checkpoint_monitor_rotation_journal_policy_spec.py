#!/usr/bin/env python3
"""RUST-149 static policy for TEST-ONLY append-only RUST-146 monitor rotation journal."""
from __future__ import annotations
import ast, hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
DOC=ROOT/'RUST_149.md'; VERIFY=ROOT/'rust_149_rust146_checkpoint_monitor_rotation_journal_verify.py'; FIXTURE=ROOT/'rust_149_rust146_checkpoint_monitor_rotation_journal_fixture.py'; SELFTEST=ROOT/'rust_149_rust146_checkpoint_monitor_rotation_journal_selftest.py'; WORKFLOW=ROOT/'.github/workflows/native-rust149-checkpoint-monitor-rotation-journal.yml'; BASE=ROOT/'rust_148_multistep_rust146_checkpoint_monitor_rotation_verify.py'; PREDECESSOR_WORKFLOW=ROOT/'.github/workflows/native-rust148-multistep-rust146-checkpoint-monitor-rotation.yml'
EXPECTED_RUST148_GIT_BLOB='a120dcc830ed6cbe834f2bb6e57b7fee7549f743'; EXPECTED_RUST148_WORKFLOW_GIT_BLOB='ab159930c52124fa68ce5a6d6d6703d24225874d'
ALLOWED_VERIFY_IMPORTS={'__future__','hashlib','pathlib','sys','rust_030_stdlib_material_verify','rust_032_external_monotonic_floor_verify','rust_146_rust145_checkpoint_monitor_verify','rust_147_rust146_checkpoint_monitor_rotation_verify','rust_148_multistep_rust146_checkpoint_monitor_rotation_verify'}
ALLOWED_SELFTEST_IMPORTS={'__future__','base64','copy','itertools','json','pathlib','sys','tempfile','rust_030_stdlib_material_verify','rust_032_external_monotonic_floor_verify','rust_146_rust145_checkpoint_monitor_verify','rust_149_rust146_checkpoint_monitor_rotation_journal_verify'}
def text(p):
    v=p.read_text(encoding='utf-8'); assert '\r' not in v; return v
def blob(raw): return hashlib.sha1(f'blob {len(raw)}\0'.encode('ascii')+raw).hexdigest()
def imported_roots(src):
    out=set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n,ast.Import): out.update(a.name.split('.',1)[0] for a in n.names)
        elif isinstance(n,ast.ImportFrom) and n.module: out.add(n.module.split('.',1)[0])
    return out
def require(hay,need,label):
    missing=[n for n in need if n not in hay]
    if missing: raise AssertionError(f'{label} missing required markers: {missing}')
def main():
    doc=text(DOC); verify=text(VERIFY); fixture=text(FIXTURE); selftest=text(SELFTEST); workflow=text(WORKFLOW); checks=0
    assert blob(BASE.read_bytes())==EXPECTED_RUST148_GIT_BLOB; assert blob(PREDECESSOR_WORKFLOW.read_bytes())==EXPECTED_RUST148_WORKFLOW_GIT_BLOB
    require(verify,('import rust_146_rust145_checkpoint_monitor_verify as monitor_verify','import rust_148_multistep_rust146_checkpoint_monitor_rotation_verify as rotation2_verify'),'composition'); checks+=1; print('[GREEN] exact reviewed RUST-148 verifier and workflow are pinned')
    assert imported_roots(verify)<=ALLOWED_VERIFY_IMPORTS; assert imported_roots(selftest)<=ALLOWED_SELFTEST_IMPORTS
    for f in ('cryptography','Ed25519PrivateKey','SEEDS=','.sign(','subprocess','requests','urllib','socket','import axven','from axven'): assert f not in verify and f not in selftest,f
    checks+=1; print('[GREEN] detached RUST-149 verifier/selftest have no signing or network capability')
    require(verify,('THRESHOLD=2','AXVEN_NATIVE_RUST149_MONITOR_ROTATION_JOURNAL_CHECKPOINT_V1','target_digest','predecessor_entry_sha256','cumulative_revoked_monitor_ids','rewrites checkpointed prefix','observed same-parent RUST-149 monitor rotation journal checkpoint fork','base_paths[308]','range(309,316)','path_args[316:320]'),'verifier'); checks+=1; print('[GREEN] append-only hash chain, evidence binding, quorum, and fork rejection are fixed')
    require(fixture,("'6f'*32","'7f'*32","'8f'*32","'9f'*32",'Ed25519PrivateKey','RUST-149 TEST-only journal monitor public-key pin mismatch'),'fixture'); require(selftest,('prefix checkpoint availability: 3/3','final checkpoint availability: 3/3','35/35 expected cases passed','observed-valid-same-parent-monitor-rotation-journal-fork'),'selftest'); checks+=1; print('[GREEN] producer-only keys and 3/3 + 3/3 + 35/35 matrix are fixed')
    require(workflow,('permissions:\n  contents: read','persist-credentials: false','python-version: "3.13.15"','chmod 0444','axven-rust149','env -i HOME=/tmp PATH=/usr/bin:/bin','/usr/bin/python3 -S','test "$(wc -l < /tmp/axven-rust149-paths)" -eq 320','test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 122','expected 316 RUST-148 paths','expected 320 RUST-149 paths'),'workflow')
    for f in ('contents: write','id-token: write','packages: write','pull-requests: write','actions/upload-artifact','attest','release','deploy'): assert f not in workflow.lower(),f
    checks+=1; print('[GREEN] workflow stays detached, read-only, and non-publishing')
    require(doc,('M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5','cumulative revocation `[M1, M2]`','2-of-3','3/3 valid two-monitor subsets','35/35 expected cases','same-parent final checkpoint','320-path','122-file','Production consensus remains Python-authoritative.'),'documentation'); checks+=1; print('[GREEN] documentation preserves TEST-only journal boundary')
    assert checks==6; print('RUST-149 static policy: 6/6 checks passed')
if __name__=='__main__': main()
