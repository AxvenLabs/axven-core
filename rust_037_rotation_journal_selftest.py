#!/usr/bin/env python3
"""RUST-037 detached fail-closed selftest; no producer/signing capability."""
from __future__ import annotations
import base64,copy,json,sys,tempfile
from pathlib import Path
import rust_030_stdlib_material_verify as material_verify
import rust_035_witness_set_rotation_verify as rotation1_verify
import rust_036_multistep_witness_rotation_verify as rotation2_verify
import rust_037_rotation_journal_verify as V

def fail(label,fn):
 try: fn()
 except (AssertionError,ValueError,json.JSONDecodeError): print(f"[GREEN] mutation rejected: {label}"); return
 raise AssertionError(f"mutation unexpectedly accepted: {label}")
def main():
 if len(sys.argv)!=16: raise SystemExit("usage: rust_037_rotation_journal_selftest.py STATE FLOOR R1 A1 Q1 R2 A2 Q2 PJ PC FJ FC FORK SOURCE FLOOR")
 st,fl,r1,a1,q1,r2,a2,q2,pj,pc,fj,fc,fork=[Path(x) for x in sys.argv[1:14]]; src,req=sys.argv[14:16]
 V.verify(st,fl,r1,a1,q1,r2,a2,q2,pj,pc,fj,fc,src,req)
 es,pr,pv,cr,cv,fr,fv,xr,xv,ps,fs=V.context(r1,r2,pj,pc,fj,fc,src); kr,kv=V.L(fork,"fork"); n=0
 def F(l,fn):
  nonlocal n; fail(l,fn); n+=1
 def JV(l,edit):
  v=copy.deepcopy(fv); edit(v); F(l,lambda:V.validate_journal(v,V.expected_journal(es,src),"final"))
 JV("journal-entry-omission",lambda v:v["entries"].pop(1)); JV("journal-entry-reorder",lambda v:v["entries"].__setitem__(slice(0,2),[v["entries"][1],v["entries"][0]])); JV("journal-rotation-digest",lambda v:v["entries"][2].__setitem__("rotation_sha256","0"*64)); JV("journal-predecessor-chain",lambda v:v["entries"][2].__setitem__("predecessor_entry_sha256","0"*64)); JV("journal-revocation-truncation",lambda v:v["entries"][2].__setitem__("cumulative_revoked_key_ids",[rotation1_verify.REVOKED_KEY_ID])); JV("journal-source",lambda v:v.__setitem__("activation_source_commit","0"*40)); JV("journal-production",lambda v:v.__setitem__("production",True))
 def CP(l,base,j,s,p,edit):
  v=copy.deepcopy(base); edit(v); F(l,lambda:V.validate_checkpoint(v,j,s,p,l))
 CP("prefix-checkpoint-below-threshold",cv,pr,ps,rotation1_verify.NEW_PINNED_WITNESSES,lambda v:v.__setitem__("witnesses",v["witnesses"][:1])); CP("prefix-checkpoint-journal-digest",cv,pr,ps,rotation1_verify.NEW_PINNED_WITNESSES,lambda v:v["statement"].__setitem__("journal_sha256","0"*64))
 def sig(v): b=bytearray(material_verify.decode_signature(v["witnesses"][0]["signature"])); b[0]^=1; v["witnesses"][0]["signature"]=base64.b64encode(b).decode()
 CP("prefix-checkpoint-signature",cv,pr,ps,rotation1_verify.NEW_PINNED_WITNESSES,sig)
 for l,k,v in [("final-checkpoint-parent","previous_checkpoint_sha256","0"*64),("final-checkpoint-entry-count","entry_count",2),("final-checkpoint-head","head_entry_sha256","0"*64),("final-checkpoint-sequence-rollback","set_sequence",1),("final-checkpoint-production","production",True)]: CP(l,xv,fr,fs,rotation2_verify.FINAL_PINNED_WITNESSES,lambda x,k=k,v=v:x["statement"].__setitem__(k,v))
 for l,k in [("final-checkpoint-revoked-a",rotation2_verify.REVOKED_A_KEY_ID),("final-checkpoint-revoked-b",rotation2_verify.REVOKED_B_KEY_ID)]: CP(l,xv,fr,fs,rotation2_verify.FINAL_PINNED_WITNESSES,lambda x,k=k:(x["witnesses"][0].__setitem__("key_id",k),x["witnesses"].sort(key=lambda z:z["key_id"])))
 with tempfile.TemporaryDirectory() as td:
  p=Path(td)/"x"; p.write_text(json.dumps(fv,indent=2)+"\n"); F("noncanonical-final-journal",lambda:V.verify(st,fl,r1,a1,q1,r2,a2,q2,pj,pc,p,fc,src,req)); p.write_text(json.dumps(xv,indent=2)+"\n"); F("noncanonical-final-checkpoint",lambda:V.verify(st,fl,r1,a1,q1,r2,a2,q2,pj,pc,fj,p,src,req)); v=copy.deepcopy(pv); v["entries"][1]["rotation_sha256"]="0"*64; p.write_bytes(V.C(v)); F("checkpointed-prefix-rewrite",lambda:V.verify(st,fl,r1,a1,q1,r2,a2,q2,p,pc,fj,fc,src,req))
 F("observed-same-parent-fork",lambda:V.reject_observed_fork(xr,xv,kr,kv)); V.reject_observed_fork(xr,xv,xr,copy.deepcopy(xv)); print("[GREEN] identical repeated checkpoint is not treated as a fork")
 if n!=21: raise AssertionError(f"unexpected RUST-037 selftest case count: {n}")
 print("RUST-037 append-only journal fail-closed contract: 21/21 expected cases passed")
if __name__=="__main__": main()
