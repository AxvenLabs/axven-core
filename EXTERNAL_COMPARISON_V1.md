# Axven External Comparison Test v1

Status: **comparison baseline / TEST-only**

Frozen Axven baseline commit:

`1917ffe1541f7946699972737056121bd5dbfc9c`

This protocol is intended for side-by-side comparison with an external revocation/quarantine system using only public, reproducible evidence. It does **not** require private keys, credentials, production node access, or unpublished Axven material.

## Scope

The current Axven comparison baseline covers the already-tested observer/monitor administration contracts:

- predecessor-authorized 2-of-3 set rotation;
- cumulative revocation;
- exact predecessor and successor-set binding;
- append-only hash-chained administration history;
- quorum-signed checkpoints;
- fail-closed rejection of validly signed conflicting same-parent views.

The relevant Axven administration path is currently **TEST-only** and uses **Ed25519** in these rotation/checkpoint specs. It is not presented as production post-quantum administration.

Production offline rejoin/recovery is **not yet claimed complete**. Rejoin cases are therefore separated below into already-tested lineage properties and explicit WIP comparison cases.

## Frozen references

### RUST-071

`O1/O2/O3 -> O2/O3/O4`

- O1 revoked.
- Rotation requires at least 2-of-3 distinct valid predecessor signatures.
- Successor evidence requires at least 2-of-3 distinct valid successor reports.
- Revoked O1 cannot reappear.
- A distinct validly signed successor view with the same parent/sequence is rejected fail-closed.

Primary files:

- `RUST_071.md`
- `rust_071_monitor_rotation_journal_observer_set_rotation_policy_spec.py`
- `.github/workflows/native-monitor-rotation-journal-observer-set-rotation.yml`

### RUST-072

`O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5`

- O1 remains revoked and O2 becomes revoked.
- Second rotation requires at least 2-of-3 valid predecessor signatures.
- Cumulative revocation is `[O1, O2]`.
- Final reports are accepted only from O3/O4/O5.
- A valid same-parent conflicting final target is rejected fail-closed.

Primary files:

- `RUST_072.md`
- `rust_072_multistep_monitor_rotation_journal_observer_set_rotation_policy_spec.py`
- `.github/workflows/native-multistep-monitor-rotation-journal-observer-set-rotation.yml`

### RUST-073

- Administration history is append-only and hash-chained.
- Every non-genesis entry binds the canonical SHA-256 of its predecessor entry.
- Prefix checkpoint: exact O2/O3/O4 set, strict 2-of-3 quorum.
- Final checkpoint: exact O3/O4/O5 set, strict 2-of-3 quorum.
- Final checkpoint binds the exact prefix checkpoint through `previous_checkpoint_sha256`.
- Validly signed same-parent conflicting checkpoints are rejected fail-closed.
- Rewrite, truncation, rollback, hash-link substitution, quorum downgrade, signer duplication and signature mutation are covered by detached fail-closed selftests.

Primary files:

- `RUST_073.md`
- `rust_073_monitor_rotation_journal_observer_rotation_journal_policy_spec.py`
- `.github/workflows/native-monitor-rotation-journal-observer-rotation-journal-v2.yml`

## Comparison matrix

| ID | Scenario | Axven expected result | Current status |
| --- | --- | --- | --- |
| A1 | Canonical predecessor set authorizes first rotation with valid 2-of-3 | ACCEPT | Tested |
| A2 | Revoked O1 attempts to reappear in successor evidence | REJECT / fail-closed | Tested |
| A3 | Canonical successor set authorizes second rotation with valid 2-of-3 | ACCEPT | Tested |
| A4 | Cumulative revocation is omitted or revoked O1/O2 is resurrected | REJECT / fail-closed | Tested |
| A5 | Two distinct validly signed views share the same parent/sequence | REJECT / fail-closed | Tested |
| A6 | Final journal preserves exact checkpointed prefix and predecessor hash chain | ACCEPT | Tested |
| A7 | Prefix/history is rewritten, truncated, rolled back, or hash links are substituted | REJECT / fail-closed | Tested |
| R1 | Node is offline during rotation and later presents only its stale pre-rotation lineage | Expected REJECT until current authorized lineage is established | **WIP production rejoin** |
| R2 | Offline node obtains the canonical newer checkpoint/lineage and verifies continuity to the current epoch | Desired ACCEPT after complete verification | **WIP production rejoin** |
| R3 | Offline node receives two competing same-parent current-epoch views during recovery | Expected REJECT / fail-closed | Underlying split-view rule tested; full production rejoin path WIP |

## Side-by-side evidence record

For each scenario, record only public/non-secret evidence.

### Axven

- frozen source commit SHA;
- observer-set sequence;
- predecessor and successor set digests where applicable;
- cumulative revoked IDs;
- predecessor/checkpoint SHA-256 bindings;
- `previous_checkpoint_sha256` where applicable;
- observed target/checkpoint digest;
- decision: `ACCEPT` or `REJECT`;
- fail-closed reason/test case.

### External system

Provide the corresponding public testnet evidence available for the same logical event, for example:

- public network/testnet identifier;
- event/proof identifier;
- block/transaction/proof reference where available;
- prior/current trust-set or quarantine-state reference;
- decision: accepted, quarantined, rejected, or recovered;
- log/proof material sufficient to establish ordering and continuity.

The external side should map its native fields to the logical comparison rather than forcing Axven field names onto a different architecture.

## Reproduction

The authoritative Axven reproduction paths are the frozen GitHub Actions workflows listed above. They:

- use Ubuntu 24.04 and Python 3.13.15;
- install the producer dependency from the hash-locked CI requirements file;
- generate deterministic TEST-only evidence;
- make evidence read-only;
- stage detached verifier-only consumers without fixture/private signing code;
- run fail-closed selftests in a stripped environment using `/usr/bin/python3 -S`.

The workflows are credentialless after checkout and have read-only repository permissions.

## Comparison rules

1. Do not exchange private keys, tokens, credentials, production access, or unpublished security-sensitive material.
2. Pin both sides to exact public versions/commits/testnet references.
3. Record expected outcome before observing the result.
4. Treat a mismatch as a finding to investigate, not as a marketing score.
5. Keep already-tested Axven behavior separate from WIP production rejoin/recovery behavior.
6. Do not describe the TEST-only Ed25519 observer/monitor administration path as production PQ administration.
7. Preserve raw public proof/log references alongside any human-readable summary.

## First external run

Recommended first pass:

1. A1 — valid 2-of-3 rotation.
2. A2 — revoked identity resurrection.
3. A5 — valid same-parent conflicting view.
4. R1 — offline during rotation, stale lineage on return.
5. R3 — competing same-parent views during recovery.

The first three establish the current tested Axven baseline. R1/R3 then expose exactly where the production offline-rejoin comparison becomes experimental.

