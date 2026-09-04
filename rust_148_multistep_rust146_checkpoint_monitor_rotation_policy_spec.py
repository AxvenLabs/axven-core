#!/usr/bin/env python3
"""RUST-148 static policy for TEST-ONLY second RUST-146 checkpoint monitor rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / 'RUST_148.md'
VERIFY = ROOT / 'rust_148_multistep_rust146_checkpoint_monitor_rotation_verify.py'
FIXTURE = ROOT / 'rust_148_multistep_rust146_checkpoint_monitor_rotation_fixture.py'
SELFTEST = ROOT / 'rust_148_multistep_rust146_checkpoint_monitor_rotation_selftest.py'
WORKFLOW = ROOT / '.github/workflows/native-rust148-multistep-rust146-checkpoint-monitor-rotation.yml'
BASE = ROOT / 'rust_147_rust146_checkpoint_monitor_rotation_verify.py'
PREDECESSOR_WORKFLOW = ROOT / '.github/workflows/native-rust147-rust146-checkpoint-monitor-rotation.yml'
EXPECTED_RUST147_GIT_BLOB = 'f61fb088d2dd3df10b4540facc5881bdb3fa815f'
EXPECTED_RUST147_WORKFLOW_GIT_BLOB = '20dfa1992dd10db09fad777088d10cdc46dd39e5'

ALLOWED_VERIFY_IMPORTS = {'__future__','hashlib','pathlib','sys','rust_030_stdlib_material_verify','rust_032_external_monotonic_floor_verify','rust_146_rust145_checkpoint_monitor_verify','rust_147_rust146_checkpoint_monitor_rotation_verify'}
ALLOWED_SELFTEST_IMPORTS = {'__future__','base64','copy','itertools','json','pathlib','sys','tempfile','rust_030_stdlib_material_verify','rust_032_external_monotonic_floor_verify','rust_146_rust145_checkpoint_monitor_verify','rust_148_multistep_rust146_checkpoint_monitor_rotation_verify'}


def text(path: Path) -> str:
    value=path.read_text(encoding='utf-8')
    if '\r' in value: raise AssertionError(f'CR forbidden: {path.name}')
    return value


def blob(raw: bytes) -> str:
    return hashlib.sha1(f'blob {len(raw)}\0'.encode('ascii') + raw).hexdigest()


def imported_roots(source: str) -> set[str]:
    roots=set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import): roots.update(alias.name.split('.',1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module: roots.add(node.module.split('.',1)[0])
    return roots


def require(haystack: str, needles: tuple[str,...], label: str) -> None:
    missing=[needle for needle in needles if needle not in haystack]
    if missing: raise AssertionError(f'{label} missing required markers: {missing}')


def main() -> None:
    doc=text(DOC); verify=text(VERIFY); fixture=text(FIXTURE); selftest=text(SELFTEST); workflow=text(WORKFLOW)
    assert blob(BASE.read_bytes()) == EXPECTED_RUST147_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST147_WORKFLOW_GIT_BLOB
    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in ('cryptography','Ed25519PrivateKey','SEEDS =','.sign(','subprocess','requests','urllib','socket','import axven','from axven'):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    require(verify,('THRESHOLD = 2','PREDECESSOR_SET_SEQUENCE = 1','FINAL_SET_SEQUENCE = 2','AXVEN_NATIVE_RUST148_MONITOR_SET_ROTATION_V2','AXVEN_NATIVE_RUST148_CHECKPOINT_MONITOR_V3','CUMULATIVE_REVOKED_MONITOR_IDS','predecessor_rotation_sha256','predecessor_rotation_auth_sha256','predecessor_successor_bundle_sha256','base_paths[308]','base_paths[310]','base_paths[311]','base_paths[312]','path_args[313:316]'),'RUST-148 verifier')
    require(fixture,("'6f' * 32","'7f' * 32","'8f' * 32","'9f' * 32",'RUST-148 TEST-only monitor public-key pin mismatch','axven-rust148-final-fork-monitor-bundle.json'),'RUST-148 fixture')
    require(selftest,('predecessor authorization availability: 3/3','final monitoring availability: 3/3','54/54 expected cases passed','first-successor-replay','observed-valid-final-same-parent-fork'),'RUST-148 selftest')
    require(workflow,('permissions:\n  contents: read','persist-credentials: false','python-version: "3.13.15"','chmod 0444','expected 316 RUST-148 paths','/usr/bin/python3 -S','rust_148_multistep_rust146_checkpoint_monitor_rotation_selftest.py'),'RUST-148 workflow')
    for forbidden in ('contents: write','id-token: write','packages: write','pull-requests: write','actions/upload-artifact','attest','release','deploy'):
        assert forbidden not in workflow.lower(), forbidden
    require(doc,('TEST-ONLY','M2/M3/M4 to M3/M4/M5','2-of-3','Production consensus remains Python-authoritative.'),'RUST-148 documentation')
    print('RUST-148 static policy: 6/6 checks passed')


if __name__ == '__main__':
    main()
