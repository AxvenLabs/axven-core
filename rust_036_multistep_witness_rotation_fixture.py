#!/usr/bin/env python3
"""RUST-036 TEST-ONLY fixture producer. Private seeds never enter detached consumer."""
from __future__ import annotations
import base64, hashlib, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rust_030_stdlib_material_verify as m
import rust_031_stdlib_trust_state_material_verify as t
import rust_035_witness_set_rotation_verify as r35
import rust_036_multistep_witness_rotation_verify as r36

OUT=Path('/tmp')
SEEDS={
 'rust-033-test-only-floor-witness-v1':'0bcea6c25bf2e920391237f68a9ff4d36f3e8800521f93016ed2b4a10c81a09f',
 'rust-034-test-only-floor-witness-b-v1':'11'*32,
 'rust-034-test-only-floor-witness-c-v1':'22'*32,
 'rust-035-test-only-floor-witness-d-v1':'33'*32,
 'rust-036-test-only-floor-witness-e-v1':'44'*32,
}
def canon(x): return m.canonical(x)
def rows(ids,pins,msg):
 out=[]
 for kid in sorted(ids):
  p=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[kid]))
  pub=p.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
  if pub!=pins[kid]: raise AssertionError('RUST-036 TEST-only public-key pin mismatch')
  out.append({'key_id':kid,'signature':base64.b64encode(p.sign(msg)).decode('ascii')})
 return out
def write(name,obj): (OUT/name).write_bytes(canon(obj))
def main():
 if len(sys.argv)!=2 or len(sys.argv[1])!=40: raise SystemExit('usage: fixture.py SOURCE_SHA')
 s=sys.argv[1]
 if any(c not in '0123456789abcdef' for c in s): raise AssertionError('invalid source sha')
 g={'schema':t.STATE_SCHEMA,'sequence':0,'scope':t.MATERIAL_PAYLOAD_TYPE,'key_id':t.OLD_KEY_ID,'public_key':t.OLD_PUBLIC_KEY.hex(),'activation_source_commit':None,'predecessor_sha256':None,'transition_sha256':None,'production':False}
 tr={'schema':t.TRANSITION_SCHEMA,'sequence':1,'scope':t.MATERIAL_PAYLOAD_TYPE,'from_key_id':t.OLD_KEY_ID,'from_public_key':t.OLD_PUBLIC_KEY.hex(),'to_key_id':t.NEW_KEY_ID,'to_public_key':t.NEW_PUBLIC_KEY.hex(),'activation_source_commit':s,'production':False}
 gr,trr=canon(g),canon(tr)
 st={'schema':t.STATE_SCHEMA,'sequence':1,'scope':t.MATERIAL_PAYLOAD_TYPE,'key_id':t.NEW_KEY_ID,'public_key':t.NEW_PUBLIC_KEY.hex(),'activation_source_commit':s,'predecessor_sha256':hashlib.sha256(gr).hexdigest(),'transition_sha256':hashlib.sha256(trr).hexdigest(),'production':False}
 sr=canon(st); t.validate_genesis(gr,g); t.validate_final_state(sr,st,gr,trr,s)
 floor={'schema':'axven-native-external-monotonic-floor-v1','provider':'test-only-monotonic-floor-simulator','sequence':1,'scope':t.MATERIAL_PAYLOAD_TYPE,'key_id':st['key_id'],'public_key':st['public_key'],'activation_source_commit':s,'state_sha256':hashlib.sha256(sr).hexdigest(),'production':False}; fr=canon(floor)
 set0,set1=r35.old_witness_set(),r35.new_witness_set()
 rot1={'schema':r35.ROTATION_SCHEMA,'sequence':r35.NEW_SET_SEQUENCE,'scope':r35.FLOOR_PAYLOAD_TYPE,'from_set_sha256':hashlib.sha256(canon(set0)).hexdigest(),'to_set':set1,'revoked_key_ids':[r35.REVOKED_KEY_ID],'activation_source_commit':s,'production':False}; rot1r=canon(rot1)
 auth1={'schema':r35.ROTATION_AUTH_SCHEMA,'algorithm':r35.ALGORITHM,'threshold':2,'payload_type':r35.ROTATION_PAYLOAD_TYPE,'payload_sha256':hashlib.sha256(rot1r).hexdigest(),'witnesses':rows(r35.OLD_PINNED_WITNESSES,r35.OLD_PINNED_WITNESSES,r35.rotation_message(rot1r)),'production':False}
 q1={'schema':r35.SUCCESSOR_QUORUM_SCHEMA,'algorithm':r35.ALGORITHM,'set_sequence':1,'set_sha256':hashlib.sha256(canon(set1)).hexdigest(),'threshold':2,'payload_type':r35.FLOOR_PAYLOAD_TYPE,'payload_sha256':hashlib.sha256(fr).hexdigest(),'witnesses':rows(r35.NEW_PINNED_WITNESSES,r35.NEW_PINNED_WITNESSES,r35.successor_message(fr)),'production':False}
 set2=r36.final_witness_set()
 rot2={'schema':r36.SECOND_ROTATION_SCHEMA,'sequence':2,'scope':r36.FLOOR_PAYLOAD_TYPE,'from_set_sha256':hashlib.sha256(canon(r36.predecessor_witness_set())).hexdigest(),'to_set':set2,'revoked_key_ids':r36.CUMULATIVE_REVOKED_KEY_IDS,'predecessor_rotation_sha256':hashlib.sha256(rot1r).hexdigest(),'activation_source_commit':s,'production':False}; rot2r=canon(rot2)
 auth2={'schema':r36.SECOND_AUTH_SCHEMA,'algorithm':r36.ALGORITHM,'threshold':2,'payload_type':r36.SECOND_ROTATION_PAYLOAD_TYPE,'payload_sha256':hashlib.sha256(rot2r).hexdigest(),'witnesses':rows(r36.PREDECESSOR_PINNED_WITNESSES,r36.PREDECESSOR_PINNED_WITNESSES,r36.second_rotation_message(rot2r)),'production':False}
 q2={'schema':r36.FINAL_QUORUM_SCHEMA,'algorithm':r36.ALGORITHM,'set_sequence':2,'set_sha256':hashlib.sha256(canon(set2)).hexdigest(),'threshold':2,'payload_type':r36.FLOOR_PAYLOAD_TYPE,'payload_sha256':hashlib.sha256(fr).hexdigest(),'witnesses':rows(r36.FINAL_PINNED_WITNESSES,r36.FINAL_PINNED_WITNESSES,r36.final_quorum_message(fr)),'production':False}
 (OUT/'axven-rust036-final-state.json').write_bytes(sr)
 for n,o in [('external-floor',floor),('first-rotation',rot1),('first-auth',auth1),('first-quorum',q1),('second-rotation',rot2),('second-auth',auth2),('final-quorum',q2)]: write('axven-rust036-'+n+'.json',o)
 print('RUST-036 TEST-only fixture producer: GREEN')
if __name__=='__main__': main()
