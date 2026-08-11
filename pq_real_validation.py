#!/usr/bin/env python3
"""Real ML-DSA / Hybrid end-to-end validation.

NO mocks and NO fallback crypto.  This script must run only when the real
`dilithium-py==1.4.0` dependency is installed.
"""
import contextlib, json
import axven, wallet

@contextlib.contextmanager
def pq_window(h1=110,h2=120):
    cfg=axven.CHAIN_CONFIG
    old=(cfg["pq_hybrid_activation_height"],cfg["pq_pure_activation_height"])
    cfg["pq_hybrid_activation_height"],cfg["pq_pure_activation_height"]=h1,h2
    try: yield
    finally:
        cfg["pq_hybrid_activation_height"],cfg["pq_pure_activation_height"]=old

def main():
    checks=[]
    def ok(name,cond):
        assert cond,name
        checks.append(name)

    # Real keygen validates the external dependency immediately.
    ed=axven.Wallet()
    ml=axven.MLDSAWallet()
    ident=wallet.WalletIdentity(
        ed_keypair=(ed.public_key,ed.private_key),
        ml_keypair=(ml.public_key,ml._secret)
    )
    ok("ML public key 1312 bytes",len(ml.public_key)==1312)
    probe=b"axven-real-pq-v1"
    sig=ml.sign(probe)
    ok("ML signature 2420 bytes",len(sig)==2420)
    ok("ML verify",bool(axven._mldsa().verify(ml.public_key,probe,sig)))

    with pq_window():
        bc=axven.Blockchain(); mp=axven.Mempool(bc)

        # Reach H1-1 entirely on N.
        for _ in range(109): bc.mine(ident.address_n)
        ok("pre-H1 tip",bc.tip.height==109)
        ok("pre-H1 validates",bc.validate())

        # N -> M migration at H1 through wallet-native pipeline.
        tx=wallet.build_transaction(
            bc,ident,axven.SCHEME_ED25519,
            recipient=ident.address_m,amount=1000,fee=100,height=110
        )
        stx=wallet.sign_transaction(ident,tx,axven.SCHEME_ED25519)
        tid=mp.add(stx)
        bc.mine(ident.address_m,mp)
        ok("N->M migration mined",bc.tip.height==110 and tid not in mp.txs)
        ok("M output created",any(
            u["recipient"]==ident.address_m and not u["coinbase"] for u in bc.utxo.values()
        ))
        ok("post-migration validates",bc.validate())

        # Real pure ML-DSA spend.
        mtx=wallet.build_transaction(
            bc,ident,axven.SCHEME_ML_DSA,
            recipient=ident.address_m,amount=500,fee=50,height=111
        )
        m1=wallet.sign_transaction(ident,mtx,axven.SCHEME_ML_DSA)
        m2=wallet.sign_transaction(ident,mtx,axven.SCHEME_ML_DSA)
        ok("hedged ML witness does not change txid",m1.txid()==m2.txid()==mtx.txid())
        mp.add(m1); bc.mine(ident.address_m,mp)
        ok("M spend mined",bc.tip.height==111)
        ok("M spend validates",bc.validate())

        # Create H output with an M spend during the hybrid window.
        hcreate=wallet.build_transaction(
            bc,ident,axven.SCHEME_ML_DSA,
            recipient=ident.address_h,amount=200,fee=25,height=112
        )
        hs=wallet.sign_transaction(ident,hcreate,axven.SCHEME_ML_DSA)
        mp.add(hs); bc.mine(ident.address_h,mp)
        ok("H output created",any(
            u["recipient"]==ident.address_h and not u["coinbase"] for u in bc.utxo.values()
        ))

        # Spend H using BOTH signatures.  Destination M is valid in hybrid window.
        htx=wallet.build_transaction(
            bc,ident,axven.SCHEME_HYBRID,
            recipient=ident.address_m,amount=100,fee=10,height=113
        )
        signed_h=wallet.sign_transaction(ident,htx,axven.SCHEME_HYBRID)
        hi=signed_h._in()[0]
        ok("H has Ed witness",bool(hi.ed_signature and hi.ed_public_key))
        ok("H has ML witness",bool(hi.ml_signature and hi.ml_public_key))
        mp.add(signed_h); bc.mine(ident.address_h,mp)
        ok("H AND spend mined",bc.tip.height==113)
        ok("H spend validates",bc.validate())

        # Hybrid downgrade: remove either half and verify consensus rejection.
        outop=axven.outpoint(signed_h.txid(),0)
        # Use the pre-spend H tx again against an H UTXO from hcreate, constructing
        # explicit malformed inputs to ensure fallback is impossible.
        hop=None; hu=None
        for op,u in bc.utxo.items():
            if u["recipient"]==ident.address_h and not u["coinbase"]:
                hop,hu=op,u; break
        if hop is not None:
            txid,idx=hop.rsplit(":",1)
            base_tx=axven.Transaction([axven.TxInput(txid,int(idx))],
                                      [axven.TxOutput(max(1,hu["amount"]-1),ident.address_m)])
            full=wallet.sign_transaction(ident,base_tx,axven.SCHEME_HYBRID)._in()[0]
            ed_only=axven.TxInput(full.prev_txid,full.index,scheme=axven.SCHEME_HYBRID,
                                  ed_signature=full.ed_signature,ed_public_key=full.ed_public_key)
            ml_only=axven.TxInput(full.prev_txid,full.index,scheme=axven.SCHEME_HYBRID,
                                  ml_signature=full.ml_signature,ml_public_key=full.ml_public_key)
            ok("H ed-only rejected",not axven.verify_input(ed_only,hu,base_tx.sighash(),114))
            ok("H ml-only rejected",not axven.verify_input(ml_only,hu,base_tx.sighash(),114))

        # Cross H2 using M coinbase only; H creation must close.
        while bc.tip.height < 120:
            bc.mine(ident.address_m)
        ok("H2 reached",bc.tip.height==120)
        ok("H forbidden at H2",not axven.output_scheme_allowed(ident.address_h,120))
        ok("M allowed at H2",axven.output_scheme_allowed(ident.address_m,120))
        ok("final chain validates",bc.validate())

    result={
        "ok":True,"checks":checks,"count":len(checks),
        "public_key_bytes":len(ml.public_key),"signature_bytes":len(sig),
        "chain_id":axven.CHAIN_ID,
        "fingerprint":axven.CONFIG_FINGERPRINT,
        "genesis_hash":axven._genesis().hash(),
    }
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":main()
