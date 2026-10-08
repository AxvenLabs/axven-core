# ARCH-001 authorization timing diagnostic audit

Research only; no architecture or production PQ scheme selected. Timing is excluded from canonical evidence, architecture scoring, consensus parameters and SLAs.

## Provenance and reviewed checkpoint

The initial workspace was clean on main at `1388c450aff436f3a9ae101f7917ad972d517502`; origin main matched. Work continues on `arch001-auth-timing-audit`. The requested diagnostic branch and origin head both identified `1d7916626e9e169744232d675a25bce00f6f4238`. This audit starts from that commit's protocol, applied to current main research. No production modules or consensus settings are changed.

Reviewed GitHub PR metadata/descriptions, merged history and current fixture interfaces for #545–#576:

| PRs | Evidence retained |
|---|---|
| #545–#549 | Three state candidates, native/token workloads, contention, disjoint ordering, comparison matrix |
| #550–#562 | Canonical source/output binding, witness sizes, native/program measurements, replay/conflict, sequences, reorg, coverage |
| #563–#571 | Native equivalence, representation deltas, sequence/growth summaries, migration reuse, readiness, unweighted snapshot, fixture-count integrity |
| #572–#576 | Cross-workload equivalence, program tradeoffs/adversarial evidence and disjoint isolation/coverage binding |

Several recent PR descriptions contain only the unfilled template; executable fixtures and merged source are the substantive evidence. Coverage/readiness labels are not proof that execution succeeds: the initial canonical bundle failed at three producer/consumer interfaces.

## Defects corrected

- Diagnostic scheme parsing previously overwrote duplicate rows and ignored unexpected output. It now requires exactly the expected status and ordered scheme rows, positive integer measurements, successful exit and empty stderr.
- Protocol validity checks now remain active under optimized Python. Source hashes are checked before and after execution; raw process medians and direct source/backend provenance are retained.
- The authorization fixture previously ignored the return value of every timed verification. Every timed call now must return `True`; the check happens after the timing interval.
- Program conflict evidence imported account/UTXO commitment helpers from the object model instead of the existing token/program module.
- Native measurement evidence referenced obsolete `payload` instead of the object canonical `data` field.
- The tradeoff snapshot expected migration `summary` rows instead of the producer's `candidates` mapping and nested compatibility counts. A local `account` → `account-state` mapping preserves the existing producer schema and candidate meaning.

Focused tests cover malformed/duplicate/missing output, child failure/stderr/timeout, size/source drift, rejected timed verification, canonical exclusion, conflict reproducibility, native measurement/replay and migration counts against the underlying matrix. Research CI runs these tests, the canonical bundle, and a separate timing diagnostic with no speed threshold.

## Measurement protocol and limitations

Five fresh processes each generate independent random wallet material and valid witnesses for the same fixed message. Each process takes seven sequential `perf_counter_ns` samples per scheme and emits their median; the protocol reports the median/min/max of those process medians and the max/min ratio. Raw process medians are retained, not individual seven-sample timings. Schemes run in fixed Ed25519/ML-DSA/hybrid order, without warm-up or CPU affinity. This is not a paired fixed-key benchmark, confidence interval, throughput test or negative-witness benchmark.

The measured boundary is existing `axven.verify_input`: decoding, recipient/scheme/height checks and signature verification. It does not measure signing, wallet generation, interpreter startup, transactions, state transitions, commitment computation, mempool/block validation or architecture-specific execution. ML-DSA verification uses pyca/OpenSSL; the optional legacy recovery package is installed for the broader validation suite but is not this verification path. Test heights are fixture inputs, not activation changes.

The isolated `/tmp` runtime uses CPython 3.13.15 and hash-locked CI dependencies, including cryptography 50.0.1. Output records OpenSSL, OS/Python versions and SHA-256 of the protocol, cost fixture and `axven.py`. These are direct sources, not a complete environment attestation: CPU/load/governor, wheel hashes, transitive code and random keys are not fully recorded. No private keys or signatures are persisted in the diagnostic report.

Canonical witness byte lengths describe JSON/base64 research representations, not raw signatures or production wire/fee/storage costs. Size-only evidence remains in the canonical bundle; timing and this audit report remain outside it. The initial diagnostic ran alongside validation, so its dispersion reflects competing local work. A subsequent standalone run is recorded below. Host background load remains uncontrolled.

## Initial validation and observed results

Run from repository root with the editable package installed; owner-only creation permissions (`umask 077`) are needed for security-sensitive POSIX fixture files. No security-repository files were opened or modified.

- Eight diagnostic regression tests pass normally and with `-O`; three integration regressions pass.
- The repaired canonical bundle passes all 30 fixtures with byte-identical reruns, source/output provenance, native/token/program comparisons, commitments, fail-closed replay/conflict, reorg and migration reuse. Bundle SHA-256: `e538952708f8a1ae59ef9d83022d8aabc413f641c0ff0118646751fd1d10879b`.
- Dependency consistency: `pip check` passes.
- Full-validation registry: 95/98 suites pass when the runner and remaining suites are combined. The standard runner stops at checkpoint 51; checkpoints 52/53 daemon initial-state assertions also fail when run separately. Exact assertions: `configured peer begins never connected`, `new daemon peer exposes empty history`, and `new daemon peer has no active incident`. These files and all production code are unchanged; these results are blockers, not waived passes.
- SEC-076+ original tail: 151/156 scripts pass across the runner and separately executed remainder; SEC-132 blocks in its synchronous socket-pair fixture, and SEC-213/215/216/218 initially reject group-writable interpreter/workspace paths. Environment-controlled rechecks are described below. No claim of a fully green original tail is made.

Standalone diagnostic after the other suites completed, on 2026-10-08 UTC (host background load uncontrolled):

| Scheme | Canonical witness bytes | Median of process medians (ns) | Min–max process median (ns) | Max/min |
|---|---:|---:|---:|---:|
| ed25519 | 253 | 241559 | 228440–261475 | 1.144611 |
| hybrid | 5312 | 577975 | 565109–804257 | 1.423189 |
| ml-dsa-44 | 5122 | 338984 | 337120–518255 | 1.537301 |

The full raw process medians and source/backend metadata are retained locally in `/tmp/ARCH001_AUTH_TIMING_DIAGNOSTIC_SAMPLE.json`, an uncommitted noncanonical diagnostic sample. The timing values must not be used to rank state architectures. A repeated invocation is expected to change timings; source hashes and witness byte lengths permit comparison of provenance without requiring timing equality.

Reproduce the research checks:

```sh
python research/programmable_l1/arch001_auth_timing_protocol_test.py
python -O research/programmable_l1/arch001_auth_timing_protocol_test.py
python research/programmable_l1/arch001_evidence_integration_test.py
python research/programmable_l1/arch001_decision_bundle.py
python research/programmable_l1/arch001_auth_timing_protocol_evidence.py
```

The research workflow adds executable checks without changing production routing. Subsequent fixture maintenance adds regression coverage to the full-validation registry, as documented in `ARCH001_VALIDATION_FIXTURE_AUDIT.md`. Any proposed PR must remain a draft while full-validation blockers exist; it must not merge without exact-head green CI, no blocking reviews and explicit user authorization.

## Baseline and environment rechecks

A pristine archive of main `1388c450` was extracted into an owner-only `/tmp/arch001-baseline-validation` directory. Checkpoints 51/52/53 daemon tests each reproduce the same failed initial-state assertions there (exit 1 each), confirming that these failures predate this research change.

SEC-213/215/216/218 each pass unmodified in that archive after removing group-write permission from the isolated `/tmp` interpreter. The shared workspace directory permissions were left unchanged. These are environment restrictions, not research regressions. With those separate rechecks, 155 of 156 security-tail scripts have successful unmodified executions; this is not a successful single end-to-end tail run.

SEC-132 was interrupted after blocking for several minutes. Its `recv_raw` helper calls `left.sendall` with approximately 1 MB before reading `right`; the local socket buffer cannot hold that entire frame. A temporary in-memory replacement of only the test helper, using a concurrent sender and bounded reader, executes all 14 SEC-132 checks successfully. No production parser or repository test was changed by that experiment. That original fixture was a Linux validation blocker; subsequent maintenance and direct original-test results are documented in `ARCH001_VALIDATION_FIXTURE_AUDIT.md`.

Local run logs are retained under `/tmp/arch001-*.log`; the standalone generated sample remains outside the repository and proposed commit. Initial default-permission and loaded-timing runs are observations, not final canonical evidence. Broad tests used the pinned CPython/runtime versions; successful isolated rechecks do not waive the full-validation/CI merge gate.
