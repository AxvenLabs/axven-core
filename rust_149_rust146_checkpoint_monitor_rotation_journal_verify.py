#!/usr/bin/env python3
"""RUST-149: TEST-ONLY append-only RUST-146 checkpoint-monitor rotation journal verifier."""
from __future__ import annotations
import hashlib
from pathlib import Path
import sys
import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_146_rust145_checkpoint_monitor_verify as monitor_verify
import rust_147_rust146_checkpoint_monitor_rotation_verify as rotation1_verify
import rust_148_multistep_rust146_checkpoint_monitor_rotation_verify as rotation2_verify

JOURNAL_SCHEMA="axven-native-rust149-monitor-rotation-journal-v1"
ENTRY_SCHEMA="axven-native-rust149-monitor-rotation-journal-entry-v1"
CHECKPOINT_SCHEMA="axven-native-rust149-monitor-rotation-journal-checkpoint-v1"
STATEMENT_SCHEMA="axven-native-rust149-monitor-rotation-journal-checkpoint-statement-v1"
CHECKPOINT_DOMAIN=b"AXVEN_NATIVE_RUST149_MONITOR_ROTATION_JOURNAL_CHECKPOINT_V1\x00"
ALGORITHM="ed25519"; THRESHOLD=2
MONITORED_CHECKPOINT_KEY=monitor_verify.CHECKPOINT_SHA_KEY
MONITORED_STATEMENT_KEY=monitor_verify.CHECKPOINT_STATEMENT_SHA_KEY
JOURNAL_KEYS=frozenset({"schema","activation_source_commit","monitored_checkpoint_sha256","monitored_checkpoint_statement_sha256","observed_target_sha256","entries","production"})
ENTRY_KEYS=frozenset({"schema","sequence","monitor_set_sha256","rotation_sha256","rotation_auth_sha256","monitor_bundle_sha256","cumulative_revoked_monitor_ids","predecessor_entry_sha256"})
CHECKPOINT_KEYS=frozenset({"schema","algorithm","threshold","statement","monitors","production"})
CHECKPOINT_MONITOR_KEYS=frozenset({"monitor_id","signature"})
STATEMENT_KEYS=frozenset({"schema","monitor_set_sequence","monitor_set_sha256","entry_count","journal_sha256","head_entry_sha256","previous_checkpoint_sha256","monitored_checkpoint_sha256","monitored_checkpoint_statement_sha256","observed_target_sha256","activation_source_commit","production"})

def canonical(v): return material_verify.canonical(v)
def sha256(raw): return hashlib.sha256(raw).hexdigest()
def set_sha(s): return sha256(canonical(s))
def target_digest(target):
    if frozenset(target)!=monitor_verify.TARGET_KEYS: raise AssertionError("unexpected RUST-149 inherited target fields")
    return sha256(canonical({k:target[k] for k in sorted(monitor_verify.TARGET_KEYS)}))

def expected_entries(old_bundle_raw,first_rotation_raw,first_auth_raw,first_successor_raw,second_rotation_raw,second_auth_raw,final_bundle_raw):
    e0={"schema":ENTRY_SCHEMA,"sequence":0,"monitor_set_sha256":set_sha(rotation1_verify.old_monitor_set()),"rotation_sha256":None,"rotation_auth_sha256":None,"monitor_bundle_sha256":sha256(old_bundle_raw),"cumulative_revoked_monitor_ids":[],"predecessor_entry_sha256":None}
    e1={"schema":ENTRY_SCHEMA,"sequence":1,"monitor_set_sha256":set_sha(rotation1_verify.new_monitor_set()),"rotation_sha256":sha256(first_rotation_raw),"rotation_auth_sha256":sha256(first_auth_raw),"monitor_bundle_sha256":sha256(first_successor_raw),"cumulative_revoked_monitor_ids":[rotation1_verify.REVOKED_MONITOR_ID],"predecessor_entry_sha256":sha256(canonical(e0))}
    e2={"schema":ENTRY_SCHEMA,"sequence":2,"monitor_set_sha256":set_sha(rotation2_verify.final_monitor_set()),"rotation_sha256":sha256(second_rotation_raw),"rotation_auth_sha256":sha256(second_auth_raw),"monitor_bundle_sha256":sha256(final_bundle_raw),"cumulative_revoked_monitor_ids":rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS,"predecessor_entry_sha256":sha256(canonical(e1))}
    return [e0,e1,e2]

def expected_journal(entries,source_sha,target): return {"schema":JOURNAL_SCHEMA,"activation_source_commit":source_sha,"monitored_checkpoint_sha256":target[MONITORED_CHECKPOINT_KEY],"monitored_checkpoint_statement_sha256":target[MONITORED_STATEMENT_KEY],"observed_target_sha256":target_digest(target),"entries":entries,"production":False}
def validate_journal(journal,expected,label):
    if not isinstance(journal,dict) or frozenset(journal)!=JOURNAL_KEYS or journal.get("schema")!=JOURNAL_SCHEMA: raise AssertionError(f"invalid {label} RUST-149 journal fields")
    if journal.get("production") is not False or journal!=expected: raise AssertionError(f"{label} RUST-149 journal continuity mismatch")
    entries=journal.get("entries")
    if not isinstance(entries,list) or not entries: raise AssertionError("empty RUST-149 journal")
    for i,e in enumerate(entries):
        if not isinstance(e,dict) or frozenset(e)!=ENTRY_KEYS or e.get("schema")!=ENTRY_SCHEMA or type(e.get("sequence")) is not int or e["sequence"]!=i: raise AssertionError("invalid RUST-149 journal entry")
        if i==0:
            if e.get("predecessor_entry_sha256") is not None: raise AssertionError("unexpected RUST-149 genesis predecessor")
        elif e.get("predecessor_entry_sha256")!=sha256(canonical(entries[i-1])): raise AssertionError("broken RUST-149 journal hash chain")
def checkpoint_statement(journal_raw,head_entry_raw,monitor_set_sequence,monitor_set,previous_checkpoint_sha256,entry_count,target,source_sha):
    return {"schema":STATEMENT_SCHEMA,"monitor_set_sequence":monitor_set_sequence,"monitor_set_sha256":set_sha(monitor_set),"entry_count":entry_count,"journal_sha256":sha256(journal_raw),"head_entry_sha256":sha256(head_entry_raw),"previous_checkpoint_sha256":previous_checkpoint_sha256,"monitored_checkpoint_sha256":target[MONITORED_CHECKPOINT_KEY],"monitored_checkpoint_statement_sha256":target[MONITORED_STATEMENT_KEY],"observed_target_sha256":target_digest(target),"activation_source_commit":source_sha,"production":False}
def checkpoint_message(statement,journal_raw):
    sr=canonical(statement); return CHECKPOINT_DOMAIN+len(sr).to_bytes(8,"big")+sr+len(journal_raw).to_bytes(8,"big")+journal_raw
def validate_checkpoint_envelope(checkpoint,journal_raw,pins,label):
    if not isinstance(checkpoint,dict) or frozenset(checkpoint)!=CHECKPOINT_KEYS or checkpoint.get("schema")!=CHECKPOINT_SCHEMA: raise AssertionError(f"invalid {label} RUST-149 checkpoint fields")
    if checkpoint.get("algorithm")!=ALGORITHM or checkpoint.get("production") is not False or type(checkpoint.get("threshold")) is not int or checkpoint["threshold"]!=THRESHOLD: raise AssertionError("invalid RUST-149 checkpoint boundary")
    st=checkpoint.get("statement")
    if not isinstance(st,dict) or frozenset(st)!=STATEMENT_KEYS or st.get("schema")!=STATEMENT_SCHEMA or st.get("production") is not False: raise AssertionError("invalid RUST-149 checkpoint statement")
    rows=checkpoint.get("monitors")
    if not isinstance(rows,list) or not (THRESHOLD<=len(rows)<=len(pins)) or not all(isinstance(r,dict) and frozenset(r)==CHECKPOINT_MONITOR_KEYS for r in rows): raise AssertionError("invalid RUST-149 signature rows")
    ids=[r["monitor_id"] for r in rows]
    if ids!=sorted(ids) or len(ids)!=len(set(ids)) or any(i not in pins for i in ids): raise AssertionError("invalid RUST-149 signer ids")
    msg=checkpoint_message(st,journal_raw)
    for r in rows: material_verify.ed25519_verify(pins[r["monitor_id"]],material_verify.decode_signature(r["signature"]),msg)
    return st
def validate_checkpoint(checkpoint,journal_raw,expected_statement,pins,label):
    if validate_checkpoint_envelope(checkpoint,journal_raw,pins,label)!=expected_statement: raise AssertionError(f"{label} RUST-149 checkpoint statement mismatch")
def reject_observed_fork(canonical_checkpoint_raw,canonical_checkpoint,observed_checkpoint_raw,observed_checkpoint,journal_raw,pins):
    left=validate_checkpoint_envelope(canonical_checkpoint,journal_raw,pins,"canonical final"); right=validate_checkpoint_envelope(observed_checkpoint,journal_raw,pins,"observed final")
    if left.get("monitor_set_sequence")==right.get("monitor_set_sequence") and left.get("previous_checkpoint_sha256")==right.get("previous_checkpoint_sha256") and canonical_checkpoint_raw!=observed_checkpoint_raw: raise AssertionError("observed same-parent RUST-149 monitor rotation journal checkpoint fork")
def verify(*args):
    if len(args)!=322: raise AssertionError("unexpected RUST-149 verifier argument count")
    *path_args,expected_source_sha,required_floor_text=args
    if len(path_args)!=320: raise AssertionError("unexpected RUST-149 path count")
    base_paths=path_args[:316]; prefix_journal_path,prefix_checkpoint_path,final_journal_path,final_checkpoint_path=path_args[316:320]
    rotation2_verify.verify(*base_paths,expected_source_sha,required_floor_text)
    monitored_checkpoint_raw,monitored_checkpoint=floor_verify.load_canonical(base_paths[308],"RUST-145 final monitor rotation checkpoint")
    target=monitor_verify.checkpoint_target(monitored_checkpoint_raw,monitored_checkpoint["statement"])
    if target["activation_source_commit"]!=expected_source_sha: raise AssertionError("RUST-149 checkpoint source mismatch")
    raws=[floor_verify.load_canonical(base_paths[i],"RUST-149 predecessor evidence")[0] for i in range(309,316)]
    entries=expected_entries(*raws)
    prefix_journal_raw,prefix_journal=floor_verify.load_canonical(prefix_journal_path,"RUST-149 prefix journal"); prefix_checkpoint_raw,prefix_checkpoint=floor_verify.load_canonical(prefix_checkpoint_path,"RUST-149 prefix checkpoint"); final_journal_raw,final_journal=floor_verify.load_canonical(final_journal_path,"RUST-149 final journal"); _,final_checkpoint=floor_verify.load_canonical(final_checkpoint_path,"RUST-149 final checkpoint")
    validate_journal(prefix_journal,expected_journal(entries[:2],expected_source_sha,target),"prefix")
    ps=checkpoint_statement(prefix_journal_raw,canonical(entries[1]),1,rotation1_verify.new_monitor_set(),None,2,target,expected_source_sha)
    validate_checkpoint(prefix_checkpoint,prefix_journal_raw,ps,rotation1_verify.NEW_PINNED_MONITORS,"prefix")
    validate_journal(final_journal,expected_journal(entries,expected_source_sha,target),"final")
    if final_journal["entries"][:2]!=prefix_journal["entries"]: raise AssertionError("final RUST-149 monitor rotation journal rewrites checkpointed prefix")
    fs=checkpoint_statement(final_journal_raw,canonical(entries[2]),2,rotation2_verify.final_monitor_set(),sha256(prefix_checkpoint_raw),3,target,expected_source_sha)
    validate_checkpoint(final_checkpoint,final_journal_raw,fs,rotation2_verify.FINAL_PINNED_MONITORS,"final")
    print(f"RUST-149 append-only RUST-146 checkpoint monitor rotation journal: GREEN source={expected_source_sha} entries=3 checkpoint={sha256(canonical(final_checkpoint))}")
def main():
    if len(sys.argv)!=324 or sys.argv[1]!="verify": raise SystemExit("usage: rust_149_rust146_checkpoint_monitor_rotation_journal_verify.py verify ... SOURCE_SHA REQUIRED_FLOOR")
    verify(*[Path(v) for v in sys.argv[2:-2]],sys.argv[-2],sys.argv[-1])
if __name__=="__main__": main()
