# ARCH-001 programmable-L1 evidence matrix

Status: **research-only / non-consensus**

This checkpoint consolidates the evidence that must exist before Axven can choose among the current UTXO baseline, an account/state model, and an Axven object/resource-state model. It does **not** select a winner and it does not alter production consensus routing or any monetary, PoW, block-target, chain-identity, or activation parameter.

## Evidence already executable on main

| Question | UTXO baseline | Account/state prototype | Object/resource prototype | Executable evidence |
|---|---|---|---|---|
| Native AXVEN transfer | consume/create outputs | balance + sequence transition | versioned balance-resource transition | `arch001_transfer_compare.py` |
| Deterministic state commitment | yes | yes | yes | `arch001_transfer_compare.py`, `arch001_invariants.py` |
| Replay rejection | spent/missing outpoint | stale sequence | stale object version | `arch001_transfer_compare.py` |
| Same-prestate conflict | spent input | stale sequence | stale object version | `arch001_contention_compare.py` |
| Disjoint transfer ordering | same final commitment for tested workload | same final commitment for tested workload | same final commitment for tested workload | `arch001_batch_order_compare.py` |
| Issued-token transfer | output-carried asset state | account asset balance | versioned token-balance resource | `arch001_token_compare.py` |
| Program-state mutation | consume/recreate state output | sequence-guarded account state | versioned program resource | `arch001_token_program_compare.py` |
| Access/conflict representation | measured research representation | measured research representation | explicit read/write object sets | `arch001_access_compare.py` |
| State-growth sensitivity | measured | measured | measured | `arch001_state_growth_compare.py` |
| Rollback/replay requirements | compared | compared | compared | `arch001_rollback_compare.py` |
| Existing-Core migration/reuse | inventoried | inventoried | inventoried | `arch001_migration_reuse_compare.py` |
| Classical / ML-DSA / hybrid auth cost | sensitivity only | sensitivity only | sensitivity only | `arch001_auth_cost_compare.py` |

The entries above mean only that the repository contains an executable comparison for the stated research question. They are not claims that the three models have equal cost, equal security properties, or equal implementation complexity.

## Decision workload gate

A final ARCH-001 recommendation MUST NOT be made until one canonical evidence bundle runs equivalent workloads through all three candidates and records, without architecture-specific scoring weights:

1. native AXVEN transfer: single, replay, same-prestate conflict, and disjoint batch ordering;
2. issued-asset transfer and a minimal mutable program-state workload;
3. deterministic pre/post state commitments and byte-identical evidence on repeat execution;
4. fail-closed rejection with proof that rejected transitions leave no partial state mutation;
5. state growth for the same logical workload and explicit state touched/read/written;
6. rollback/reorg restoration requirements from the same committed pre-state;
7. classical, ML-DSA and hybrid witness-size / verification-cost sensitivity without selecting a production PQ scheme;
8. migration/reuse impact, including which current Core validation, storage, wallet, networking, mempool, reorg and commitment components can remain unchanged, need adapters, or require replacement.

## Required interpretation discipline

A candidate may be better on one axis and worse on another. In particular, compact state, explicit conflict sets, familiar wallet semantics, migration cost, PQ witness overhead, and programmable-state ergonomics are distinct axes. ARCH-001 must preserve the raw measurements and observations before any policy weighting is applied.

A future recommendation therefore needs two separate artifacts:

- **measurement evidence**: deterministic machine-produced values and pass/fail invariants;
- **decision policy**: explicit human-chosen weights/trade-offs applied only after the evidence is complete.

No architecture is selected by this matrix.

## Hard scope boundary

Everything under this ARCH-001 research track remains outside production consensus routing. This research must not change current main consensus semantics, AXVEN monetary parameters, PoW rules, block target, chain identity, or activation heights. Any future production proposal requires a separate design/review/activation process after ARCH-001 is complete.
