#!/usr/bin/env python3
"""SEC-195: meter explicit/manual peer sync with persistent outbound work budgets."""
from __future__ import annotations
import inspect
import axven
import core as core_module
import p2p

class FakeClock:
    def __init__(self): self.now=1000.0
    def __call__(self): return self.now

def install_tiny_budgets(core,clock):
    core._outbound_sync_block_work_limiter=p2p._OutboundSyncBlockWorkLimiter(
        clock=clock,global_rate=1,global_burst=2,
        per_host_rate=1,per_host_burst=2,max_hosts=4,
    )
    core._outbound_sync_block_signature_work_limiter=p2p._OutboundSyncBlockSignatureWorkLimiter(
        clock=clock,global_rate=1,global_burst=2,
        per_host_rate=1,per_host_burst=2,max_hosts=4,
    )

def main():
    checks=[]
    def green(name,condition=True):
        assert condition,name
        checks.append(name); print('[GREEN]',name)

    manual=core_module.AxvenCore(); clock=FakeClock(); install_tiny_budgets(manual,clock)
    block_id=id(manual._outbound_sync_block_work_limiter)
    sig_id=id(manual._outbound_sync_block_signature_work_limiter)
    calls=[]; original=p2p.sync_to_peer
    def fake_sync(address,session,**kwargs):
        bg=kwargs.get('block_work_gate'); sg=kwargs.get('block_signature_work_gate')
        assert callable(bg) and callable(sg)
        b=bg(); s=sg(1); calls.append((address,b,s)); return int(b and s)
    p2p.sync_to_peer=fake_sync
    try:
        first=manual.sync_peer('198.51.100.7',18444,128)
        second=manual.sync_peer('198.51.100.7',18444,128)
        third=manual.sync_peer('198.51.100.7',18444,128)
    finally:p2p.sync_to_peer=original
    green('manual sync wires persistent block and signature gates',
          [r[1:] for r in calls]==[(True,True),(True,True),(False,False)])
    green('manual reconnects preserve limiter instances',
          id(manual._outbound_sync_block_work_limiter)==block_id and
          id(manual._outbound_sync_block_signature_work_limiter)==sig_id)
    green('manual sync stops at exhausted persistent budget',(first,second,third)==(1,1,0))

    shared=core_module.AxvenCore(); peer=shared.add_outbound_peer(('203.0.113.9',18444))
    shared_clock=FakeClock(); install_tiny_budgets(shared,shared_clock); rows=[]
    def fake_shared(address,session,**kwargs):
        b=kwargs['block_work_gate'](); s=kwargs['block_signature_work_gate'](1)
        rows.append((address,b,s)); return int(b and s)
    p2p.sync_to_peer=fake_shared
    try:
        explicit=shared.sync_peer(peer[0],peer[1],128)
        configured=shared.sync_outbound_peer(peer)
        explicit_again=shared.sync_peer(peer[0],peer[1],128)
    finally:p2p.sync_to_peer=original
    green('manual and configured sync share one per-host budget',
          (explicit,configured['accepted'],explicit_again)==(1,1,0) and
          [r[1:] for r in rows]==[(True,True),(True,True),(False,False)])
    green('configured peer remains healthy at shared budget edge',
          configured['ok'] is True and shared.peer_last_error.get(peer) is None)

    manual_src=inspect.getsource(core_module.AxvenCore.sync_peer)
    auto_src=inspect.getsource(core_module.AxvenCore.sync_outbound_peer)
    green('production manual sync reuses core-owned limiters',
          '_outbound_sync_block_work_limiter.consume(source_host)' in manual_src and
          '_outbound_sync_block_signature_work_limiter.consume' in manual_src and
          'block_work_gate=block_gate' in manual_src and
          'block_signature_work_gate=signature_gate' in manual_src and
          '_OutboundSyncBlockWorkLimiter(' not in manual_src)
    green('automatic configured sync budget wiring remains present',
          '_outbound_sync_block_work_limiter.consume(source_host)' in auto_src and
          '_outbound_sync_block_signature_work_limiter.consume' in auto_src)
    green('p2p catch-up remains caller-gated with bounded default rounds',
          inspect.signature(p2p.sync_to_peer).parameters['max_rounds'].default==100 and
          inspect.signature(p2p.sync_to_peer).parameters['limit'].default==128)
    green('SEC-195 preserves canonical chain and PQ identity',
          axven.CHAIN_ID=='axven-devnet-2' and
          axven.CONFIG_FINGERPRINT=='ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae' and
          axven.CHAIN_CONFIG['pq_hybrid_activation_height']==2000 and
          axven.CHAIN_CONFIG['pq_pure_activation_height']==5000 and
          axven.Blockchain().tip.hash()=='a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3')
    assert len(checks)==9
    print('SEC-195 manual sync work budget: 9/9 GREEN')

if __name__=='__main__': main()
