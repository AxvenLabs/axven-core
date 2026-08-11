#!/usr/bin/env python3
import copy, random
import axven

def u(amount, recipient, height=1, coinbase=False):
    return {"amount":amount,"recipient":recipient,"coinbase":coinbase,"height":height}

def main():
    checks=[]
    def ok(name, cond):
        assert cond, name
        checks.append(name)

    # Empty / deterministic rebuild.
    t=axven.SparseMerkleTree()
    ok("empty root", t.root == axven.SMT_EMPTY_ROOT == axven.smt_root_reference({}))
    state={}
    rng=random.Random(887)

    # Property test: every incremental mutation equals the untouched reference.
    live=[]
    for n in range(220):
        if live and rng.random() < .38:
            op=rng.choice(live); live.remove(op); state.pop(op)
            t.update(op,None)
        else:
            op=axven.sha256(f"op-{n}-{rng.random()}".encode())+":0"
            val=u(rng.randint(1,10_000_000), "N"+axven.sha256(op.encode())[:40],
                  rng.randint(1,500), bool(rng.getrandbits(1)))
            state[op]=val
            if op not in live: live.append(op)
            t.update(op,val)
        ok(f"root match {n}", t.root == axven.smt_root_reference(state))

    # Update existing value.
    if live:
        op=live[0]
        state[op]=u(999999,"N"+axven.sha256(b"updated")[:40],777,False)
        t.update(op,state[op])
        ok("update existing",t.root==axven.smt_root_reference(state))

    # Rebuild order independence.
    rev={k:state[k] for k in reversed(list(state))}
    t2=axven.SparseMerkleTree(rev)
    ok("rebuild reference",t2.root==axven.smt_root_reference(state))
    ok("order independent",t2.root==t.root)

    # Inclusion proof.
    op=next(iter(state))
    p=t.prove(op)
    ok("inclusion proof",axven.smt_verify_proof(op,p["value"],p["siblings"],p["root"]))
    bad=copy.deepcopy(p["value"]); bad["amount"]+=1
    ok("tampered inclusion rejected",not axven.smt_verify_proof(op,bad,p["siblings"],p["root"]))

    # Non-inclusion proof.
    missing=axven.sha256(b"missing-op")+":9"
    p=t.prove(missing)
    ok("non-inclusion value none",p["value"] is None)
    ok("non-inclusion proof",axven.smt_verify_proof(missing,None,p["siblings"],p["root"]))

    # Tampered sibling/root rejected.
    sib=list(p["siblings"]); sib[0]="11"*32
    ok("tampered sibling rejected",not axven.smt_verify_proof(missing,None,sib,p["root"]))
    ok("wrong root rejected",not axven.smt_verify_proof(missing,None,p["siblings"],"22"*32))

    # Batch changes equal sequential/reference.
    deletes=list(state)[:min(7,len(state))]
    puts={}
    for i in range(9):
        op=axven.sha256(f"batch-{i}".encode())+":1"
        puts[op]=u(100+i,"N"+axven.sha256(op.encode())[:40],900+i,False)
    for op in deletes: state.pop(op,None)
    state.update(puts)
    t.apply_changes(deletes,puts)
    ok("batch root",t.root==axven.smt_root_reference(state))

    print(f"SMT incremental: {len(checks)}/{len(checks)} GREEN")
    print("root",t.root)
    print("stored_nondefault_nodes",len(t.nodes))

if __name__=="__main__": main()
