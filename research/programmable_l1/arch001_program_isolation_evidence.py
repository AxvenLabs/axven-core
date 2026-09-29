#!/usr/bin/env python3
"""ARCH-001 research-only disjoint program-state isolation evidence."""
from copy import deepcopy
from arch001_model import AxvenObject, canonical_bytes, commitment, state_commitment
from arch001_token_program_compare import account_program_increment, object_program_increment, utxo_program_increment

def roots(u,a,o):
    return (commitment(u), commitment(a), state_commitment(o))

def base():
    return (
      {"a:0":{"owner":"program:a","asset":"STATE","amount":7},"b:0":{"owner":"program:b","asset":"STATE","amount":20}},
      {"program:a":{"counter":7,"sequence":0},"program:b":{"counter":20,"sequence":0}},
      {"a":AxvenObject("a","program:a","counter",0,{"value":7},"program-policy"),"b":AxvenObject("b","program:b","counter",0,{"value":20},"program-policy")}
    )

def apply(s,spent,name):
    u,a,o=s
    utxo_program_increment(u,spent,name+":0",name+":1")
    account_program_increment(a,"program:"+name,0)
    object_program_increment(o,name,0)

def reject(fn):
    try: fn()
    except ValueError as e: return str(e)
    raise AssertionError("stale transition accepted")

def run_once():
    initial=base()
    ab=tuple(deepcopy(x) for x in initial); sab=set()
    apply(ab,sab,"a"); apply(ab,sab,"b")
    ba=tuple(deepcopy(x) for x in initial); sba=set()
    apply(ba,sba,"b"); apply(ba,sba,"a")
    assert roots(*ab)==roots(*ba)
    before=roots(*ab)
    errors=(
      reject(lambda:utxo_program_increment(ab[0],sab,"a:0","a:2")),
      reject(lambda:account_program_increment(ab[1],"program:a",0)),
      reject(lambda:object_program_increment(ab[2],"a",0)),
    )
    assert roots(*ab)==before
    assert ab[0]["b:1"]["amount"]==ab[1]["program:b"]["counter"]==ab[2]["b"].data["value"]==21
    return {"schema":"axven-arch001-program-isolation-v1","scope":"research-only; outside production consensus routing","ab_roots":list(before),"ba_roots":list(roots(*ba)),"order_converges":True,"stale_a_errors":list(errors),"rejected_a_preserves_commitments":True,"independent_b_preserved":True,"architecture_selected":False}

def main():
    x=run_once(); y=run_once()
    assert canonical_bytes(x)==canonical_bytes(y)
    print("ARCH-001 program isolation evidence: 6/6 GREEN")
    print(canonical_bytes(x).decode("ascii"))
    print("NOTE research-only; no scheduler or architecture selected")

if __name__=="__main__": main()
