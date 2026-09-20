# ARCH-001 — Programmable L1 State & Execution Architecture

Status: RESEARCH ONLY
Base main: 641a669bb84d2f9a5d8d83b09698a0cd10ed786e

## Purpose

Determine which state and execution architecture should underpin a future programmable Axven Layer 1 without changing current production-authoritative consensus.

Axven currently has a UTXO-oriented transaction/state model. ARCH-001 treats that implementation as the baseline, not as a predetermined final architecture.

## Hard boundaries

ARCH-001 MUST NOT:

- change current consensus rules or chain identity;
- change monetary parameters, block target, PoW rules, or activation heights;
- replace the current UTXO implementation on main;
- claim a production smart-contract runtime exists;
- select a VM, language, or final state model before comparative evidence exists;
- weaken Ed25519, ML-DSA-44, or hybrid authorization checks.

Research prototypes MUST remain outside production consensus routing.

## Existing components to preserve and evaluate for reuse

- block/chain and cumulative-chainwork/reorg infrastructure;
- TCP P2P and bounded untrusted-message handling;
- persistent storage/replay infrastructure;
- Sparse Merkle state commitment primitives;
- RPC/operator boundaries;
- Ed25519, ML-DSA-44, and hybrid authorization work;
- existing regression/security tests where semantics remain applicable.

## Architecture candidates

### A — Current UTXO baseline

Use the existing input/output and UTXO state transition as the control implementation.

### B — Account/state prototype

Model persistent accounts with sequence/replay protection, native balance, authorization policy, and program-owned state.

### C — Object/resource-state prototype

Model state as versioned objects/resources with explicit ownership/authority and declared read/write access.

Initial research object:

    AxvenObject {
        object_id
        owner_or_authority
        object_type
        version
        data
        authorization_policy
    }

Initial research transaction envelope:

    AxvenResearchTransaction {
        sender
        sequence
        read_set[]
        write_set[]
        program_id
        arguments[]
        resource_limit
        authorization_policy
        witness
    }

These names and fields are research hypotheses, not protocol commitments.

## Required workloads

Each candidate must be evaluated with equivalent deterministic workloads:

1. native AXVEN transfer;
2. user-issued token creation and transfer;
3. simple program-owned state mutation;
4. independent transactions touching disjoint state;
5. conflicting transactions touching the same state;
6. replayed transaction;
7. deterministic replay from the same pre-state;
8. reorg/rollback simulation where applicable;
9. Ed25519, ML-DSA-44, and hybrid authorization size/cost sensitivity.

## Required evidence

For every prototype report:

- canonical transaction bytes or canonical research encoding;
- pre-state and post-state commitments;
- deterministic replay result;
- conflict/replay rejection result;
- state growth;
- transaction/witness size;
- execution time as diagnostic evidence only;
- opportunities and constraints for parallel execution;
- migration/reuse impact on current Axven Core.

No benchmark is a consensus promise or SLA.

## Decision criteria

The eventual architecture review must compare:

- determinism;
- fail-closed behavior;
- replay resistance;
- reorg/rollback complexity;
- state growth and commitment cost;
- PQ/hybrid signature overhead;
- parallel execution potential;
- developer ergonomics;
- token and application expressiveness;
- program-to-program interaction;
- resource/gas accounting complexity;
- wallet/RPC/SDK impact;
- migration cost from the current Core;
- crypto-agility and authorization-policy evolution.

ARCH-001 does not select a winner.

## First implementation checkpoint

Build research-only canonical data structures and deterministic state-transition prototypes under research/programmable_l1/.

The first checkpoint must prove only:

- canonical encoding is byte-deterministic;
- identical pre-state + transaction yields identical post-state;
- stale object/account version or sequence is rejected fail-closed;
- conflicting writes are detected;
- disjoint access sets can be identified without claiming production parallel execution.

Only after those invariants are executable should token/program semantics be expanded.
