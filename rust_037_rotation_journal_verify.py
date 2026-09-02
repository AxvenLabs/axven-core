#!/usr/bin/env python3
"""RUST-037 TEST-ONLY append-only rotation journal/checkpoint verifier."""
from __future__ import annotations
import base64,copy,hashlib,json,sys,tempfile
from pathlib import Path
import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_035_witness_set_rotation_verify as rotation1_verify
import rust_036_multistep_witness_rotation_verify as rotation2_verify
JOURNAL_SCHEMA="axven-native-witness-rotation-journal-v1"
ENTRY_SCHEMA="axven-native-witness-rotation-journal-entry-v1"
CHECKPOINT_SCHEMA="axven-native-witness-rotation-journal-checkpoint-v1"
STATEMENT_SCHEMA="axven-native-witness-rotation-journal-checkpoint-statement-v1"
CHECKPOINT_DOMAIN=b"AXVEN_NATIVE_WITNESS_ROTATION_JOURNAL_CHECKPOINT_V1\x00"
ALGORITHM="ed25519"
JK=frozenset({"schema","activation_source_commit","entries","production"}); EK=frozenset({"schema","sequence","set_sha256","rotation_sha256","cumulative_revoked_key_ids","predecessor_entry_sha256"}); CK=frozenset({"schema","algorithm","statement","witnesses"}); SK=frozenset({"schema","set_sequence","set_sha256","entry_count","journal_sha256","head_entry_sha256","previous_checkpoint_sha256","production"})
def C(x): return material_verify.canonical(x)
def H(x): return hashlib.sha256(x).hexdigest()
def SH(x): return H(C(x))
def expected_entries(r1,r2):
 e0={"schema":ENTRY_SCHEMA,"sequence":0,"set_sha256":SH(rotation1_verify.old_witness_set()),"rotation_sha256":None,"cumulative_revoked_key_ids":[],"predecessor_entry_sha256":None}
 e1={"schema":ENTRY_SCHEMA,"sequence":1,"set_sha256":SH(rotation1_verify.new_witness_set()),"rotation_sha256":H(r1),"cumulative_revoked_key_ids":[rotation1_verify.REVOKED_KEY_ID],"predecessor_entry_sha256":H(C(e0))}
 e2={"schema":ENTRY_SCHEMA,"sequence":2,"set_sha256":SH(rotation2_verify.final_witness_set()),"rotation_sha256":H(r2),"cumulative_revoked_key_ids":rotation2_verify.CUMULATIVE_REVOKED_KEY_IDS,"predecessor_entry_sha256":H(C(e1))}; return [e0,e1,e2]
def expected_journal(es,s): return {"schema":JOURNAL_SCHEMA,"activation_source_commit":s,"entries":es,"production":False}
def validate_journal(j,e,l):
 if frozenset(j)!=JK or j.get("schema")!=JOURNAL_SCHEMA or j.get("production") is not False or j!=e: raise AssertionError(f"{l} journal continuity mismatch")
 for i,x in enumerate(j.get("entries",[])):
  if not isinstance(x,dict) or frozenset(x)!=EK or x.get("schema")!=ENTRY_SCHEMA or x.get("sequence")!=i: raise AssertionError(f"non-monotonic {l} journal sequence")
def checkpoint_statement(j,h,seq,ws,prev,n): return {"schema":STATEMENT_SCHEMA,"set_sequence":seq,"set_sha256":SH(ws),"entry_count":n,"journal_sha256":H(j),"head_entry_sha256":H(h),"previous_checkpoint_sha256":prev,"production":False}
def checkpoint_message(s,j):
 r=C(s); return CHECKPOINT_DOMAIN+len(r).to_bytes(8,"big")+r+len(j).to_bytes(8,"big")+j
def validate_checkpoint(c,j,s,p,l):
 if frozenset(c)!=CK or c.get("schema")!=CHECKPOINT_SCHEMA or c.get("algorithm")!=ALGORITHM or c.get("statement")!=s or not isinstance(c.get("statement"),dict) or frozenset(c["statement"])!=SK or c["statement"].get("production") is not False: raise AssertionError(f"{l} checkpoint statement mismatch")
 rotation1_verify._validate_signatures(c.get("witnesses"),p,checkpoint_message(s,j),f"{l} checkpoint")
def reject_observed_fork(ar,a,br,b):
 x=a.get("statement") if isinstance(a,dict) else None; y=b.get("statement") if isinstance(b,dict) else None
 if not isinstance(x,dict) or not isinstance(y,dict): raise AssertionError("invalid fork checkpoint statement")
 if x.get("set_sequence")==y.get("set_sequence") and x.get("previous_checkpoint_sha256")==y.get("previous_checkpoint_sha256") and ar!=br: raise AssertionError("observed same-parent checkpoint fork")
def L(p,n): return floor_verify.load_canonical(p,n)
def context(r1,r2,pj,pc,fj,fc,source):
 a,_=L(r1,"r1"); b,_=L(r2,"r2"); es=expected_entries(a,b); pr,pv=L(pj,"pj"); cr,cv=L(pc,"pc"); fr,fv=L(fj,"fj"); xr,xv=L(fc,"fc")
 ps=checkpoint_statement(pr,C(es[1]),1,rotation1_verify.new_witness_set(),None,2); fs=checkpoint_statement(fr,C(es[2]),2,rotation2_verify.final_witness_set(),H(cr),3); return es,pr,pv,cr,cv,fr,fv,xr,xv,ps,fs
def verify(st,fl,r1,a1,q1,r2,a2,q2,pj,pc,fj,fc,src,req):
 rotation2_verify.verify(st,fl,r1,a1,q1,r2,a2,q2,src,req); es,pr,pv,cr,cv,fr,fv,xr,xv,ps,fs=context(r1,r2,pj,pc,fj,fc,src)
 validate_journal(pv,expected_journal(es[:2],src),"prefix"); validate_checkpoint(cv,pr,ps,rotation1_verify.NEW_PINNED_WITNESSES,"prefix"); validate_journal(fv,expected_journal(es,src),"final")
 if fv["entries"][:2]!=pv["entries"]: raise AssertionError("final journal rewrites checkpointed prefix")
 validate_checkpoint(xv,fr,fs,rotation2_verify.FINAL_PINNED_WITNESSES,"final"); print(f"RUST-037 append-only rotation journal: GREEN source={src} entries=3 checkpoint={H(C(xv))}")
def main():
 if len(sys.argv)!=16 or sys.argv[1]!="verify": raise SystemExit("usage: rust_037_rotation_journal_verify.py verify ...")
 a=[Path(x) for x in sys.argv[2:-2]]; verify(*a,sys.argv[-2],sys.argv[-1])
if __name__=="__main__": main()
