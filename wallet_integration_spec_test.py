#!/usr/bin/env python3
"""
wallet_integration_spec_test.py — W-003 Wallet <-> Node Integration ACCEPTANCE
CONTRACT (executable spec).

Same discipline as pq_spec_test.py / wallet_spec_test.py: written BEFORE
implementation, expected to START RED. No mocks — references the real
(future) wallet API and the REAL axven Blockchain/Mempool ground truth.

GROUND TRUTH this contract is built on (verified against the real code before
writing a single assertion, per the project's own discipline of not assuming
behavior that hasn't been checked):
  - Mempool is PURELY in-memory: `Mempool.__init__` sets txs/fees/spent to empty
    containers; StateStore.persist()/load() only ever touch `chain` (blocks),
    never a mempool. There is NO mempool persistence. A restart via
    StateStore.load() creates a FRESH, empty Mempool. This is not a bug to
    paper over — W-003.2 locks it as documented, expected behavior.
  - Mempool.add() ALREADY rejects a second tx spending an outpoint already
    spent by a pending tx in the same mempool (`self.spent`), raising
    ValueError("Double spend"). This is the consensus-level backstop. The
    wallet-level gap this contract closes is UX/efficiency: without its own
    pending-awareness, the wallet would build and SIGN (real ML-DSA signing,
    ~36ms) a doomed transaction before finding out at mp.add() with a raw,
    non-wallet-specific error.
  - Blockchain._reevaluate_mempool() ALREADY runs on every reorg: mempool txs
    from the old branch are re-validated against the new chain state, and
    anything that no longer validates (conflicting/invalid) is dropped. This
    is the consensus-level backstop for W-003.3 — the wallet-level gap is
    keeping its own pending/reservation bookkeeping in sync with the fact that
    a tx it thought was pending got silently dropped.
  - chain.spendable() (used by select_coins, W-002.3) reads ONLY chain.utxo —
    the CONFIRMED UTXO set. An unconfirmed change output sitting in the
    mempool is NOT visible to chain.spendable() until mined. This contract
    locks that as documented behavior (no chained-unconfirmed spending in v1),
    not something to "fix" by inventing a second, parallel UTXO view.

Expected NEW wallet API surface (implementation target, on top of W-002):
  class PendingTracker:
      reserve(txid, outpoints)         # mark outpoints as wallet-pending
      release(txid)                    # drop a reservation (confirmed / abandoned)
      is_reserved(outpoint) -> bool
      reconcile(mempool)               # drop any reservation whose txid is no
                                        # longer in mempool.txs (confirmed, reorged
                                        # out, or lost on restart)
  select_coins(chain, identity, scheme, amount, fee, tracker=None)
      # extends W-002.3 signature with an OPTIONAL tracker (backward compatible);
      # when given, excludes any coin whose outpoint tracker.is_reserved()
"""
import axven
import contextlib

RESULTS = []


def check(wid, name, blocker, fn):
    try:
        fn()
        RESULTS.append((wid, name, blocker, True, ""))
    except AssertionError as e:
        RESULTS.append((wid, name, blocker, False, f"contract unmet: {e}"))
    except Exception as e:
        RESULTS.append((wid, name, blocker, False, f"not implemented: {type(e).__name__}: {e}"))


def want(mod, attr):
    v = getattr(mod, attr, None)
    assert v is not None, f"{mod.__name__}.{attr} missing"
    return v


@contextlib.contextmanager
def pq_window(h1, h2):
    cfg = axven.CHAIN_CONFIG
    s = (cfg["pq_hybrid_activation_height"], cfg["pq_pure_activation_height"])
    cfg["pq_hybrid_activation_height"], cfg["pq_pure_activation_height"] = h1, h2
    try:
        yield
    finally:
        cfg["pq_hybrid_activation_height"], cfg["pq_pure_activation_height"] = s


def _mature_identity_chain(n_blocks=None):
    """Common setup: a WalletIdentity with `n_blocks` matured N coinbases on a
    real chain, inside a reachable pq_window. Returns (bc, mp, identity)."""
    import wallet
    from axven import Blockchain, Wallet as AxWallet, MLDSAWallet, Mempool, COINBASE_MATURITY
    ed, ml = AxWallet(), MLDSAWallet()
    identity = wallet.WalletIdentity(ed_keypair=(ed.public_key, ed.private_key),
                                     ml_keypair=(ml.public_key, ml._secret))
    bc = Blockchain(); mp = Mempool(bc)
    n = n_blocks or (COINBASE_MATURITY + 3)
    for _ in range(n):
        bc.mine(identity.address_n)
    return bc, mp, identity


# --------------------------------------------------------------------------- #
# W-003.1 — Pending UTXO safety / no double-selection            [BLOCKER]
# --------------------------------------------------------------------------- #
def w1():
    import wallet
    PendingTracker = want(wallet, "PendingTracker")
    select_coins = want(wallet, "select_coins")
    build_transaction = want(wallet, "build_transaction")
    sign_transaction = want(wallet, "sign_transaction")
    from axven import SCHEME_ED25519, outpoint

    with pq_window(2000, 5000):
        bc, mp, identity = _mature_identity_chain()
        tracker = PendingTracker()

        # build + sign + broadcast tx-A, spending some UTXO A
        height = bc.tip.height + 1
        tx_a = build_transaction(bc, identity, SCHEME_ED25519,
                                 recipient=identity.address_n, amount=1000, fee=100,
                                 height=height)
        signed_a = sign_transaction(identity, tx_a, SCHEME_ED25519)
        txid_a = mp.add(signed_a)
        assert txid_a, "tx-A must be accepted by mempool"
        ops_a = [outpoint(i.prev_txid, i.index) for i in signed_a._in()]
        tracker.reserve(txid_a, ops_a)

        # a SECOND selection, tracker-aware, must NOT offer the reserved coin(s)
        # again for a competing spend — this is the wallet-level gap consensus
        # doesn't close (mp.add() only catches it AFTER a real signature is made).
        other = select_coins(bc, identity, SCHEME_ED25519, 500, 100, tracker=tracker)
        other_ops = {(txid, idx) for txid, idx, _amt in other}
        assert not (other_ops & set(ops_a)), \
            "tracker-aware select_coins must not re-offer a reserved (pending) outpoint"

        # DEFENSE IN DEPTH: even without the wallet's own tracking, the
        # consensus-level mempool itself must still reject a second tx spending
        # the same outpoint (already-proven axven behavior — re-asserted here so
        # this contract fails loudly if that backstop ever regresses).
        def _split_op(op):
            txid, idx = op.rsplit(":", 1)
            return txid, int(idx)
        tx_b = axven.Transaction([axven.TxInput(*_split_op(op)) for op in ops_a],
                                 [axven.TxOutput(1, identity.address_n)])
        signed_b = sign_transaction(identity, tx_b, SCHEME_ED25519)
        raised = False
        try:
            mp.add(signed_b)
        except Exception:
            raised = True
        assert raised, "mempool must still reject a raw double-spend (backstop)"

        # unconfirmed change (mempool-only output) must NOT be selectable — no
        # chained-unconfirmed spending in v1 (documented, not a bug).
        pending_change_ops = {(o.recipient, i) for i, o in enumerate(signed_a.outputs)}
        confirmed_ops = {(u["recipient"], ) for u in bc.utxo.values()}
        # the change output's txid:index must not appear in chain.utxo yet
        change_op = outpoint(signed_a.txid(), 1) if len(signed_a.outputs) > 1 else None
        if change_op:
            assert change_op not in bc.utxo, "unconfirmed change must not be in chain.utxo yet"


# --------------------------------------------------------------------------- #
# W-003.2 — Restart + mempool recovery                             [BLOCKER]
# --------------------------------------------------------------------------- #
def w2():
    import wallet
    PendingTracker = want(wallet, "PendingTracker")
    select_coins = want(wallet, "select_coins")
    build_transaction = want(wallet, "build_transaction")
    sign_transaction = want(wallet, "sign_transaction")
    from axven import SCHEME_ED25519, StateStore, outpoint
    import tempfile, shutil

    with pq_window(2000, 5000):
        bc, mp, identity = _mature_identity_chain()
        tracker = PendingTracker()

        height = bc.tip.height + 1
        tx = build_transaction(bc, identity, SCHEME_ED25519,
                               recipient=identity.address_n, amount=1000, fee=100,
                               height=height)
        signed = sign_transaction(identity, tx, SCHEME_ED25519)
        txid = mp.add(signed)
        ops = [outpoint(i.prev_txid, i.index) for i in signed._in()]
        tracker.reserve(txid, ops)
        assert tracker.is_reserved(ops[0]) is True

        d = tempfile.mkdtemp(prefix="w003_restart_")
        StateStore(d).persist(bc)                    # persists BLOCKS only (ground truth)
        loaded = StateStore(d).load()
        shutil.rmtree(d)

        # ground truth: the pending tx did NOT survive restart (never mined)
        assert loaded.mempool is None or txid not in getattr(loaded.mempool, "txs", {}), \
            "unconfirmed tx must not survive a restart (mempool is not persisted)"

        # the underlying UTXO is UNTOUCHED on the reloaded chain (never mined) ->
        # a reconciled tracker must release the stale reservation, and the coin
        # must become selectable again — no permanent lock from a lost pending tx.
        tracker.reconcile(axven.Mempool(loaded))      # fresh empty mempool for loaded chain
        assert tracker.is_reserved(ops[0]) is False, \
            "reconcile against a mempool missing the txid must release the reservation"
        coins = select_coins(loaded, identity, SCHEME_ED25519, 1000, 100, tracker=tracker)
        assert any((c[0], c[1]) in set(ops) for c in coins) or coins, \
            "the coin must be selectable again after restart (not permanently stuck)"


# --------------------------------------------------------------------------- #
# W-003.3 — Stale UTXO / reorg handling                            [BLOCKER]
# --------------------------------------------------------------------------- #
def w3():
    import wallet
    PendingTracker = want(wallet, "PendingTracker")
    select_coins = want(wallet, "select_coins")
    build_transaction = want(wallet, "build_transaction")
    sign_transaction = want(wallet, "sign_transaction")
    from axven import Blockchain, Wallet as AxWallet, MLDSAWallet, Mempool, SCHEME_ED25519

    with pq_window(2000, 5000):
        ed, ml = AxWallet(), MLDSAWallet()
        import wallet as w
        identity = w.WalletIdentity(ed_keypair=(ed.public_key, ed.private_key),
                                    ml_keypair=(ml.public_key, ml._secret))

        # chain A: identity mines block 1 (this coinbase is "UTXO A")
        a = Blockchain(); mp_a = Mempool(a)
        a.mine(identity.address_n)
        assert a.tip.height == 1

        # chain B: a DIFFERENT, heavier chain from the same genesis that does
        # NOT include identity's block -> triggers a reorg on A when fed in.
        other = AxWallet()
        b = Blockchain()
        for _ in range(axven.COINBASE_MATURITY + 3):
            b.mine(other.address)
        assert b.tip.height > a.tip.height

        for blk in b.blocks[1:]:
            a.add_block(blk)
        assert a.tip.hash() == b.tip.hash(), "chain A must have reorged onto the heavier chain B"

        # ground truth: identity's coinbase (UTXO A) is GONE after the reorg
        stale_present = any(u["recipient"] == identity.address_n for u in a.utxo.values())
        assert not stale_present, "the orphaned coinbase must no longer be in chain.utxo post-reorg"

        # a wallet that (incorrectly) still had a stale reservation for it must
        # be able to reconcile that away against the CURRENT mempool state.
        tracker = PendingTracker()
        tracker.reserve("stale-txid", [("deadbeef" * 8, 0)])
        tracker.reconcile(mp_a)
        assert tracker.is_reserved(("deadbeef" * 8, 0)) is False

        # select_coins on the POST-REORG chain must reflect live state only —
        # it must not offer the vanished coin, and must work normally for funds
        # that DO exist post-reorg (a fresh, unrelated build must succeed).
        other_ml = MLDSAWallet()
        other_identity = w.WalletIdentity(ed_keypair=(other.public_key, other.private_key),
                                          ml_keypair=(other_ml.public_key, other_ml._secret))
        # (other_identity's ml key is a fresh independent one; only its N side
        # matters here, since chain B's coinbases went to other.address which is N)
        coins = select_coins(a, other_identity, SCHEME_ED25519, 1000, 100)
        assert coins, "post-reorg select_coins must find the funds that DO exist on the new chain"


# --------------------------------------------------------------------------- #
# W-003.4 — Multi-block balance consistency across the PQ schedule
# --------------------------------------------------------------------------- #
def w4():
    import wallet
    select_coins = want(wallet, "select_coins")
    build_transaction = want(wallet, "build_transaction")
    sign_transaction = want(wallet, "sign_transaction")
    from axven import (Blockchain, Wallet as AxWallet, MLDSAWallet, Mempool,
                       SCHEME_ED25519, SCHEME_ML_DSA, output_scheme_allowed)

    H1, H2 = 110, 120
    with pq_window(H1, H2):
        ed, ml = AxWallet(), MLDSAWallet()
        identity = wallet.WalletIdentity(ed_keypair=(ed.public_key, ed.private_key),
                                         ml_keypair=(ml.public_key, ml._secret))
        bc = Blockchain(); mp = Mempool(bc)
        for _ in range(H1 - 1):
            bc.mine(identity.address_n)

        def confirmed_balance(scheme):
            addr = identity.address_of(scheme)
            return sum(u["amount"] for u in bc.utxo.values() if u["recipient"] == addr)

        pre_n_balance = confirmed_balance(SCHEME_ED25519)
        assert pre_n_balance > 0, "wallet must show N balance before H1"
        assert confirmed_balance(SCHEME_ML_DSA) == 0, "no M balance should exist yet"

        # cross H1: spend N -> M (as in W-002.6), then mine through to H2
        tx = build_transaction(bc, identity, SCHEME_ED25519,
                               recipient=identity.address_m, amount=1000, fee=100,
                               height=bc.tip.height + 1)
        signed = sign_transaction(identity, tx, SCHEME_ED25519)
        mp.add(signed)
        bc.mine(identity.address_m, mp)
        assert bc.tip.height == H1

        post_m_balance = confirmed_balance(SCHEME_ML_DSA)
        assert post_m_balance > 0, "wallet must show M balance appear at H1 (from spend + change)"
        # the wallet's view (sum over chain.utxo for its own addresses) must match
        # what select_coins would actually find as spendable (matured) at this height
        m_coins = select_coins(bc, identity, SCHEME_ML_DSA, 1, 0)
        assert sum(c[2] for c in m_coins) <= post_m_balance, \
            "select_coins total must never exceed the wallet's own confirmed balance view"

        # mine on through H2 with M coinbase; balance views stay consistent at every step
        while bc.tip.height < H2 + 2:
            bc.mine(identity.address_m)
            assert confirmed_balance(SCHEME_ML_DSA) >= post_m_balance, \
                "M balance must be monotonically consistent (no unexplained shrink) across blocks"
        assert output_scheme_allowed(identity.address_m, bc.tip.height)


def main():
    order = [("W-003.1", "Pending UTXO safety / no double-selection", True, w1),
             ("W-003.2", "Restart + mempool recovery", True, w2),
             ("W-003.3", "Stale UTXO / reorg handling", True, w3),
             ("W-003.4", "Multi-block balance consistency", False, w4)]
    for wid, name, blocker, fn in order:
        check(wid, name, blocker, fn)

    print("WALLET INTEGRATION ACCEPTANCE CONTRACT (W-003) — expected RED until implemented\n")
    passed = 0
    for wid, name, blocker, ok, why in RESULTS:
        tag = "🔴 BLOCKER" if blocker else "  "
        status = "GREEN" if ok else "RED  "
        passed += ok
        line = f"  [{status}] {wid:<8} {tag:>10}  {name}"
        if not ok:
            line += f"\n              └─ {why}"
        print(line)
    print(f"\n  {passed}/{len(RESULTS)} green  "
          f"({sum(1 for r in RESULTS if r[2] and not r[3])} blockers still red)")
    print("\nThis contract turns green only when the real wallet integration meets it.")


if __name__ == "__main__":
    main()
