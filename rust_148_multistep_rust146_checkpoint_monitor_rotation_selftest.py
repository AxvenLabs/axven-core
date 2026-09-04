#!/usr/bin/env python3
"""RUST-148 detached second monitor-set rotation availability/fail-closed selftest."""
from __future__ import annotations

import base64
import copy
import itertools
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_146_rust145_checkpoint_monitor_verify as monitor_verify
import rust_148_multistep_rust146_checkpoint_monitor_rotation_verify as rotation2_verify


def fail(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def replacement_for(field: str):
    if field == 'activation_source_commit': return '0' * 40
    if field in {'monitor_set_sequence', 'entry_count'}: return 1
    return '0' * 64


def main() -> None:
    if len(sys.argv) != 320:
        raise SystemExit('usage: rust_148_multistep_rust146_checkpoint_monitor_rotation_selftest.py ... FINAL_BUNDLE FORK_BUNDLE SOURCE_SHA REQUIRED_FLOOR')
    base = [Path(value) for value in sys.argv[1:-3]]
    fork_path = Path(sys.argv[-3])
    source_sha, required_floor = sys.argv[-2:]
    if len(base) != 316:
        raise AssertionError('unexpected RUST-148 selftest base path count')

    rotation2_verify.verify(*base, source_sha, required_floor)
    checkpoint_raw, checkpoint = floor_verify.load_canonical(base[308], 'RUST-145 final monitor rotation checkpoint')
    second_rotation_raw, second_rotation = floor_verify.load_canonical(base[313], 'RUST-148 second monitor rotation')
    _, second_auth = floor_verify.load_canonical(base[314], 'RUST-148 second rotation authorization')
    _, final_bundle = floor_verify.load_canonical(base[315], 'RUST-148 final monitor bundle')
    target = monitor_verify.checkpoint_target(checkpoint_raw, checkpoint['statement'])

    auth_ok = 0
    for subset in itertools.combinations(second_auth['monitors'], rotation2_verify.THRESHOLD):
        candidate = copy.deepcopy(second_auth); candidate['monitors'] = list(subset)
        rotation2_verify.validate_rotation_auth(candidate, second_rotation_raw); auth_ok += 1
    if auth_ok != 3: raise AssertionError('unexpected RUST-148 authorization subset count')
    print('[GREEN] RUST-148 predecessor authorization availability: 3/3 valid two-monitor subsets accepted')

    final_ok = 0
    for subset in itertools.combinations(final_bundle['reports'], rotation2_verify.THRESHOLD):
        candidate = copy.deepcopy(final_bundle); candidate['reports'] = list(subset)
        rotation2_verify.validate_final_bundle(candidate, target); final_ok += 1
    if final_ok != 3: raise AssertionError('unexpected RUST-148 final monitoring subset count')
    print('[GREEN] RUST-148 final monitoring availability: 3/3 valid two-monitor subsets accepted')

    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        def write(name: str, value: dict) -> Path:
            path = root / name; path.write_bytes(material_verify.canonical(value)); return path
        def run_with(index: int, path: Path) -> None:
            paths = list(base); paths[index] = path
            rotation2_verify.verify(*paths, source_sha, required_floor)
        def reject(label: str, index: int, value: dict) -> None:
            nonlocal cases
            fail(label, lambda: run_with(index, write(f'{cases:02d}.json', value))); cases += 1

        value=copy.deepcopy(second_rotation); value['sequence']=1; reject('rotation-sequence-rollback',313,value)
        value=copy.deepcopy(second_rotation); value['from_set_sha256']='0'*64; reject('rotation-predecessor-set',313,value)
        value=copy.deepcopy(second_rotation); value['to_set']['threshold']=1; reject('rotation-final-set',313,value)
        value=copy.deepcopy(second_rotation); value['cumulative_revoked_monitor_ids']=value['cumulative_revoked_monitor_ids'][:1]; reject('rotation-cumulative-revocation',313,value)
        for key in ('predecessor_rotation_sha256','predecessor_rotation_auth_sha256','predecessor_successor_bundle_sha256'):
            value=copy.deepcopy(second_rotation); value[key]='0'*64; reject('rotation-'+key,313,value)
        value=copy.deepcopy(second_rotation); value['production']=True; reject('rotation-production',313,value)
        for field in sorted(monitor_verify.TARGET_KEYS):
            value=copy.deepcopy(second_rotation); value[field]=replacement_for(field); reject('rotation-target-'+field,313,value)

        value=copy.deepcopy(second_auth); value['threshold']=1; reject('auth-threshold',314,value)
        value=copy.deepcopy(second_auth); value['monitors']=value['monitors'][:1]; reject('auth-below-threshold',314,value)
        value=copy.deepcopy(second_auth); value['monitors']=[value['monitors'][0],copy.deepcopy(value['monitors'][0])]; reject('auth-duplicate',314,value)
        value=copy.deepcopy(second_auth); value['monitors']=list(reversed(value['monitors'])); reject('auth-unsorted',314,value)
        value=copy.deepcopy(second_auth); value['payload_sha256']='0'*64; reject('auth-payload',314,value)
        value=copy.deepcopy(second_auth); sig=bytearray(material_verify.decode_signature(value['monitors'][0]['signature'])); sig[0]^=1; value['monitors'][0]['signature']=base64.b64encode(bytes(sig)).decode('ascii'); reject('auth-signature',314,value)
        value=copy.deepcopy(second_auth); value['production']=True; reject('auth-production',314,value)

        value=copy.deepcopy(final_bundle); value['threshold']=1; reject('final-threshold',315,value)
        value=copy.deepcopy(final_bundle); value['reports']=value['reports'][:1]; reject('final-below-threshold',315,value)
        value=copy.deepcopy(final_bundle); value['reports'][1]=copy.deepcopy(value['reports'][0]); reject('final-duplicate',315,value)
        value=copy.deepcopy(final_bundle); value['reports']=list(reversed(value['reports'])); reject('final-unsorted',315,value)
        value=copy.deepcopy(final_bundle); value['final_monitor_set_sequence']=1; reject('final-set-sequence',315,value)
        value=copy.deepcopy(final_bundle); value['final_monitor_set_sha256']='0'*64; reject('final-set-digest',315,value)
        value=copy.deepcopy(final_bundle); value['reports'][0]['statement']['final_monitor_set_sequence']=1; reject('final-statement-set-sequence',315,value)
        value=copy.deepcopy(final_bundle); value['reports'][0]['statement']['final_monitor_set_sha256']='0'*64; reject('final-statement-set-digest',315,value)
        value=copy.deepcopy(final_bundle); value['reports'][0]['statement']['monitor_id']=rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS[0]; reject('revoked-m1-resurrection',315,value)
        value=copy.deepcopy(final_bundle); value['reports'][0]['statement']['monitor_id']=rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS[1]; reject('revoked-m2-resurrection',315,value)
        value=copy.deepcopy(final_bundle); value['production']=True; reject('final-production',315,value)
        value=copy.deepcopy(final_bundle); sig=bytearray(material_verify.decode_signature(value['reports'][-1]['signature'])); sig[-1]^=1; value['reports'][-1]['signature']=base64.b64encode(bytes(sig)).decode('ascii'); reject('final-signature',315,value)
        for field in sorted(monitor_verify.TARGET_KEYS):
            value=copy.deepcopy(final_bundle); value['reports'][0]['statement'][field]=replacement_for(field); reject('final-target-'+field,315,value)

        noncanonical=root/'noncanonical.json'; noncanonical.write_text(json.dumps(final_bundle,indent=2)+'\n',encoding='utf-8')
        fail('noncanonical-final-bundle',lambda:run_with(315,noncanonical)); cases+=1
        fail('first-successor-replay',lambda:run_with(315,base[312])); cases+=1
        fail('observed-valid-final-same-parent-fork',lambda:run_with(315,fork_path)); cases+=1

    if cases != 54:
        raise AssertionError(f'unexpected RUST-148 selftest case count: {cases}')
    print('RUST-148 multi-step monitor rotation fail-closed contract: 54/54 expected cases passed')


if __name__ == '__main__':
    main()
