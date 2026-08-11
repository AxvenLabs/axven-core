#!/usr/bin/env python3
import copy, tempfile, shutil
import axven

PIN_FP='ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae'
PIN_GEN='a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3'

def ok(name, cond):
    print(('PASS' if cond else 'FAIL'), '-', name)
    assert cond, name

w=axven.Wallet()
ok('config fingerprint pin', axven.CONFIG_FINGERPRINT==PIN_FP)
ok('genesis hash pin', axven._genesis().hash()==PIN_GEN)
ok('genesis state root legacy empty', axven._genesis().utxo_state_root==axven.EMPTY_ROOT)

bc=axven.Blockchain()
for _ in range(8): bc.mine(w.address)
ok('PoW every active block', all(b.pow_ok() for b in bc.blocks[1:]))
ok('chainwork increases', bc.chainwork > axven.work_of(axven.MAX_TARGET))
ok('legacy state root matches live UTXO', bc.tip.utxo_state_root==axven.utxo_root(bc.utxo))
ok('full replay validates', bc.validate())

# Heavier-chain reorg with disjoint miner.
a=axven.Blockchain(); b=axven.Blockchain(); wa=axven.Wallet(); wb=axven.Wallet()
for _ in range(2): a.mine(wa.address)
for _ in range(4): b.mine(wb.address)
old=a.tip.hash()
for blk in b.blocks[1:]: a.add_block(blk)
ok('heavier chainwork wins', a.tip.hash()==b.tip.hash() and a.tip.hash()!=old)
ok('reorg UTXO exact', a.utxo==b.utxo)
ok('reorg validates', a.validate())

# Sparse activation boundary on a test-only small height.
old_act=axven.CHAIN_CONFIG['smt_activation_height']
try:
    axven.CHAIN_CONFIG['smt_activation_height']=3
    c=axven.Blockchain(); wc=axven.Wallet()
    c.mine(wc.address); c.mine(wc.address); c.mine(wc.address)
    ok('height 2 legacy', c.blocks[2].utxo_state_root==axven.utxo_root(c._replay_prefix(2)) if hasattr(c,'_replay_prefix') else axven.state_root_scheme(2)=='legacy')
    ok('height 3 sparse scheme', axven.state_root_scheme(3)=='sparse')
    ok('height 3 sparse root matches reference', c.tip.utxo_state_root==axven.smt_root_reference(c.utxo))
    ok('sparse-boundary chain validates', c.validate())
finally:
    axven.CHAIN_CONFIG['smt_activation_height']=old_act

# Persistence roundtrip.
d=tempfile.mkdtemp(prefix='axven_cp2_')
try:
    st=axven.StateStore(d); st.persist(bc); loaded=st.load()
    ok('persistence tip exact', loaded.tip.hash()==bc.tip.hash())
    ok('persistence UTXO exact', loaded.utxo==bc.utxo)
    ok('mempool not persisted', loaded.mempool is None)
finally:
    shutil.rmtree(d)

# Byte cap is a real consensus rule.
cap=axven.CHAIN_CONFIG['max_block_bytes']
try:
    cand=bc.build_candidate(w.address)
    axven.CHAIN_CONFIG['max_block_bytes']=max(1, axven.serialized_block_size(cand)-1)
    ok('byte cap rejects candidate', axven._check_context(cand, bc.blocks, cand.height) is not None)
finally:
    axven.CHAIN_CONFIG['max_block_bytes']=cap

print('\nConsensus rebuild regression passed.')
