#!/usr/bin/env python3
"""RUST-149 detached availability and fail-closed journal selftest."""
from __future__ import annotations
import base64, copy, itertools, json, sys, tempfile
from pathlib import Path
import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_146_rust145_checkpoint_monitor_verify as monitor_verify
import rust_149_rust146_checkpoint_monitor_rotation_journal_verify as journal_verify

def fail(label,fn):
    try: fn()
    except (AssertionError,ValueError,json.JSONDecodeError):
        print(f'[GREEN] mutation rejected: {label}'); return
    raise AssertionError(f'mutation unexpectedly accepted: {label}')
def main():
    if len(sys.argv)!=324: raise SystemExit('usage: rust_149_rust146_checkpoint_monitor_rotation_journal_selftest.py ... FINAL_CHECKPOINT FORK_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR')
    base=[Path(v) for v in sys.argv[1:-3]]; fork_path=Path(sys.argv[-3]); source_sha,required_floor=sys.argv[-2:]
    if len(base)!=320: raise AssertionError('unexpected RUST-149 selftest base path count')
    journal_verify.verify(*base,source_sha,required_floor)
    mraw,m=floor_verify.load_canonical(base[308],'RUST-145 final monitor rotation checkpoint'); target=monitor_verify.checkpoint_target(mraw,m['statement'])
    raws=[floor_verify.load_canonical(base[i],'RUST-149 predecessor evidence')[0] for i in range(309,316)]; entries=journal_verify.expected_entries(*raws)
    pjr,pj=floor_verify.load_canonical(base[316],'RUST-149 prefix journal'); pcr,pc=floor_verify.load_canonical(base[317],'RUST-149 prefix checkpoint'); fjr,fj=floor_verify.load_canonical(base[318],'RUST-149 final journal'); fcr,fc=floor_verify.load_canonical(base[319],'RUST-149 final checkpoint'); fkr,fkc=floor_verify.load_canonical(fork_path,'RUST-149 observed fork checkpoint')
    ps=journal_verify.checkpoint_statement(pjr,material_verify.canonical(entries[1]),1,journal_verify.rotation1_verify.new_monitor_set(),None,2,target,source_sha)
    fs=journal_verify.checkpoint_statement(fjr,material_verify.canonical(entries[2]),2,journal_verify.rotation2_verify.final_monitor_set(),journal_verify.sha256(pcr),3,target,source_sha)
    if sum(1 for sub in itertools.combinations(pc['monitors'],2) if not journal_verify.validate_checkpoint(dict(pc,monitors=list(sub)),pjr,ps,journal_verify.rotation1_verify.NEW_PINNED_MONITORS,'prefix subset'))!=3: raise AssertionError('unexpected RUST-149 prefix subset count')
    print('[GREEN] RUST-149 prefix checkpoint availability: 3/3 valid two-monitor subsets accepted')
    if sum(1 for sub in itertools.combinations(fc['monitors'],2) if not journal_verify.validate_checkpoint(dict(fc,monitors=list(sub)),fjr,fs,journal_verify.rotation2_verify.FINAL_PINNED_MONITORS,'final subset'))!=3: raise AssertionError('unexpected RUST-149 final subset count')
    print('[GREEN] RUST-149 final checkpoint availability: 3/3 valid two-monitor subsets accepted')
    cases=0
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        def write(name,v):
            p=root/name; p.write_bytes(material_verify.canonical(v)); return p
        def run(index,path):
            paths=list(base); paths[index]=path; journal_verify.verify(*paths,source_sha,required_floor)
        muts=[]
        def add(label,index,obj,mut):
            nonlocal cases
            v=copy.deepcopy(obj); mut(v); fail(label,lambda:run(index,write(f'{len(muts)}.json',v))); muts.append(label); cases+=1
        add('prefix-genesis-set-rewrite',316,pj,lambda v:v['entries'][0].__setitem__('monitor_set_sha256','0'*64))
        add('prefix-first-rotation-digest',316,pj,lambda v:v['entries'][1].__setitem__('rotation_sha256','0'*64))
        add('prefix-first-auth-digest',316,pj,lambda v:v['entries'][1].__setitem__('rotation_auth_sha256','0'*64))
        add('prefix-monitored-checkpoint',316,pj,lambda v:v.__setitem__('monitored_checkpoint_sha256','0'*64))
        add('prefix-monitored-statement',316,pj,lambda v:v.__setitem__('monitored_checkpoint_statement_sha256','0'*64))
        add('prefix-observed-target',316,pj,lambda v:v.__setitem__('observed_target_sha256','0'*64))
        add('prefix-source',316,pj,lambda v:v.__setitem__('activation_source_commit','0'*40))
        add('prefix-production',316,pj,lambda v:v.__setitem__('production',True))
        add('final-entry-truncation',318,fj,lambda v:v.__setitem__('entries',v['entries'][:2]))
        add('final-prefix-rewrite',318,fj,lambda v:v['entries'][0].__setitem__('monitor_bundle_sha256','0'*64))
        add('final-sequence-rollback',318,fj,lambda v:v['entries'][2].__setitem__('sequence',1))
        add('final-predecessor-entry',318,fj,lambda v:v['entries'][2].__setitem__('predecessor_entry_sha256','0'*64))
        add('final-rotation-digest',318,fj,lambda v:v['entries'][2].__setitem__('rotation_sha256','0'*64))
        add('final-rotation-auth-digest',318,fj,lambda v:v['entries'][2].__setitem__('rotation_auth_sha256','0'*64))
        add('final-monitor-bundle',318,fj,lambda v:v['entries'][2].__setitem__('monitor_bundle_sha256','0'*64))
        add('final-revocation-omission',318,fj,lambda v:v['entries'][2].__setitem__('cumulative_revoked_monitor_ids',[journal_verify.rotation1_verify.REVOKED_MONITOR_ID]))
        add('prefix-threshold',317,pc,lambda v:v.__setitem__('threshold',1))
        add('prefix-below-threshold',317,pc,lambda v:v.__setitem__('monitors',v['monitors'][:1]))
        add('prefix-duplicate',317,pc,lambda v:v.__setitem__('monitors',[v['monitors'][0],copy.deepcopy(v['monitors'][0])]))
        def badsig(v):
            b=bytearray(material_verify.decode_signature(v['monitors'][0]['signature'])); b[0]^=1; v['monitors'][0]['signature']=base64.b64encode(bytes(b)).decode('ascii')
        add('prefix-signature',317,pc,badsig)
        for label,key,val in [('final-previous-checkpoint','previous_checkpoint_sha256','0'*64),('final-head-entry','head_entry_sha256','0'*64),('final-monitored-checkpoint','monitored_checkpoint_sha256','0'*64),('final-monitored-statement','monitored_checkpoint_statement_sha256','0'*64),('final-observed-target','observed_target_sha256','0'*64),('final-source','activation_source_commit','0'*40),('final-production','production',True),('final-monitor-set-sequence','monitor_set_sequence',1),('final-monitor-set-digest','monitor_set_sha256','0'*64)]: add(label,319,fc,lambda v,k=key,x=val:v['statement'].__setitem__(k,x))
        add('final-threshold',319,fc,lambda v:v.__setitem__('threshold',1)); add('final-below-threshold',319,fc,lambda v:v.__setitem__('monitors',v['monitors'][:1]))
        def badfinal(v):
            b=bytearray(material_verify.decode_signature(v['monitors'][-1]['signature'])); b[-1]^=1; v['monitors'][-1]['signature']=base64.b64encode(bytes(b)).decode('ascii')
        add('final-signature',319,fc,badfinal)
        ncj=root/'noncanonical-journal.json'; ncj.write_text(json.dumps(fj,indent=2)+'\n',encoding='utf-8'); fail('noncanonical-final-journal',lambda:run(318,ncj)); cases+=1
        ncc=root/'noncanonical-checkpoint.json'; ncc.write_text(json.dumps(fc,indent=2)+'\n',encoding='utf-8'); fail('noncanonical-final-checkpoint',lambda:run(319,ncc)); cases+=1
        fail('observed-valid-same-parent-monitor-rotation-journal-fork',lambda:journal_verify.reject_observed_fork(fcr,fc,fkr,fkc,fjr,journal_verify.rotation2_verify.FINAL_PINNED_MONITORS)); cases+=1
    if cases!=35: raise AssertionError(f'unexpected RUST-149 selftest case count: {cases}')
    print('RUST-149 monitor rotation journal fail-closed contract: 35/35 expected cases passed')
if __name__=='__main__': main()
