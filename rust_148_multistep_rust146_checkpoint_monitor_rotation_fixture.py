#!/usr/bin/env python3
"""RUST-148 TEST-ONLY second monitor-set rotation producer."""
from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_146_rust145_checkpoint_monitor_verify as monitor_verify
import rust_147_rust146_checkpoint_monitor_rotation_verify as rotation1_verify
import rust_148_multistep_rust146_checkpoint_monitor_rotation_verify as rotation2_verify

OUT = Path('/tmp')
SEEDS = {
    monitor_verify.MONITOR_2_ID: '6f' * 32,
    monitor_verify.MONITOR_3_ID: '7f' * 32,
    rotation1_verify.M4_ID: '8f' * 32,
    rotation2_verify.M5_ID: '9f' * 32,
}


def private_for(monitor_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[monitor_id]))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != pins[monitor_id]:
        raise AssertionError('RUST-148 TEST-only monitor public-key pin mismatch')
    return private


def auth_rows(rotation_raw: bytes) -> list[dict]:
    message = rotation2_verify.rotation_message(rotation_raw)
    return [{
        'monitor_id': monitor_id,
        'signature': base64.b64encode(private_for(monitor_id, rotation2_verify.PREDECESSOR_PINNED_MONITORS).sign(message)).decode('ascii'),
    } for monitor_id in sorted(rotation2_verify.PREDECESSOR_PINNED_MONITORS)]


def final_report(monitor_id: str, target: dict, set_sha: str) -> dict:
    statement = {
        'schema': rotation2_verify.FINAL_STATEMENT_SCHEMA,
        'monitor_id': monitor_id,
        'final_monitor_set_sequence': rotation2_verify.FINAL_SET_SEQUENCE,
        'final_monitor_set_sha256': set_sha,
        **target,
        'production': False,
    }
    return {
        'schema': rotation2_verify.FINAL_REPORT_SCHEMA,
        'algorithm': rotation2_verify.ALGORITHM,
        'statement': statement,
        'signature': base64.b64encode(private_for(monitor_id, rotation2_verify.FINAL_PINNED_MONITORS).sign(rotation2_verify.final_message(statement))).decode('ascii'),
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40:
        raise SystemExit('usage: rust_148_multistep_rust146_checkpoint_monitor_rotation_fixture.py SOURCE_SHA')
    source_sha = sys.argv[1]
    checkpoint_raw, checkpoint = floor_verify.load_canonical(OUT / 'axven-rust145-final-monitor-rotation-checkpoint.json', 'RUST-145 final monitor rotation checkpoint')
    first_rotation_raw, _ = floor_verify.load_canonical(OUT / 'axven-rust147-monitor-set-rotation.json', 'RUST-148 first monitor-set rotation')
    first_auth_raw, _ = floor_verify.load_canonical(OUT / 'axven-rust147-monitor-set-rotation-auth.json', 'RUST-148 first monitor-set rotation authorization')
    first_successor_raw, _ = floor_verify.load_canonical(OUT / 'axven-rust147-successor-monitor-bundle.json', 'RUST-148 first successor monitor bundle')
    target = monitor_verify.checkpoint_target(checkpoint_raw, checkpoint['statement'])
    if target['activation_source_commit'] != source_sha:
        raise AssertionError('RUST-148 checkpoint source mismatch')
    rotation = {
        'schema': rotation2_verify.ROTATION_SCHEMA,
        'sequence': rotation2_verify.FINAL_SET_SEQUENCE,
        'from_set_sha256': rotation2_verify.sha256(material_verify.canonical(rotation1_verify.new_monitor_set())),
        'to_set': rotation2_verify.final_monitor_set(),
        'cumulative_revoked_monitor_ids': rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS,
        'predecessor_rotation_sha256': rotation2_verify.sha256(first_rotation_raw),
        'predecessor_rotation_auth_sha256': rotation2_verify.sha256(first_auth_raw),
        'predecessor_successor_bundle_sha256': rotation2_verify.sha256(first_successor_raw),
        **target,
        'production': False,
    }
    rotation_raw = material_verify.canonical(rotation)
    auth = {
        'schema': rotation2_verify.ROTATION_AUTH_SCHEMA,
        'algorithm': rotation2_verify.ALGORITHM,
        'threshold': rotation2_verify.THRESHOLD,
        'payload_type': rotation2_verify.ROTATION_PAYLOAD_TYPE,
        'payload_sha256': hashlib.sha256(rotation_raw).hexdigest(),
        'monitors': auth_rows(rotation_raw),
        'production': False,
    }
    set_sha = rotation2_verify.sha256(material_verify.canonical(rotation2_verify.final_monitor_set()))
    reports = [final_report(mid, target, set_sha) for mid in sorted(rotation2_verify.FINAL_PINNED_MONITORS)]
    bundle = {
        'schema': rotation2_verify.FINAL_BUNDLE_SCHEMA,
        'final_monitor_set_sequence': rotation2_verify.FINAL_SET_SEQUENCE,
        'final_monitor_set_sha256': set_sha,
        'threshold': rotation2_verify.THRESHOLD,
        'reports': reports,
        'production': False,
    }
    (OUT / 'axven-rust148-second-monitor-set-rotation.json').write_bytes(rotation_raw)
    (OUT / 'axven-rust148-second-monitor-set-rotation-auth.json').write_bytes(material_verify.canonical(auth))
    (OUT / 'axven-rust148-final-monitor-bundle.json').write_bytes(material_verify.canonical(bundle))
    print('RUST-148 TEST-only second monitor-set rotation fixture: GREEN')


if __name__ == '__main__':
    main()
