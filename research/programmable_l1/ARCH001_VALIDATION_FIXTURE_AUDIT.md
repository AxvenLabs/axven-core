# ARCH-001 validation fixture investigation

Research/test maintenance only. Production source, consensus routing, monetary parameters, PoW, block target, chain identity and activation settings are unchanged. The canonical decision bundle still has 30 fixtures and digest `e538952708f8a1ae59ef9d83022d8aabc413f641c0ff0118646751fd1d10879b`. Timing remains diagnostic only.

## Exact causes

Checkpoint 51/52/53 fixtures save an offline peer, start the daemon, wait for RPC readiness, and assert an untouched peer state. In `axven_core.main`, RPC starts before the automatic initial outbound sync. RPC readiness is not a synchronization barrier for that sync: it may complete before the test's first peer query. The captured original checkpoint-51 snapshot was `offline`, transition count 1, consecutive failures 1, history `never_connected → offline`, and incident active. Checkpoints 52/53 read the same already-mutated state and therefore fail their empty-history/no-incident assertions. This is a real fixture race, not incorrect production health accounting. Host scheduling affects when it manifests; it also reproduced on pristine main. Changing production startup or accepting multiple initial states would conceal the test's intended lifecycle.

The test-only `daemon_startup_test_support` wrapper pauses only the first `AxvenCore.sync_outbound_peers` call until the parent completes all original initial-state assertions and writes the exact release byte. It then calls the original method, and every subsequent automatic retry uses the original implementation. Release is bounded (15 seconds), fails closed on EOF/wrong signal, and is also performed during cleanup after an assertion failure. Normal daemon entry points never import the helper. The original offline/backoff/recovery, counts, history, incident and daemon-liveness assertions remain intact.

SEC-132's original `recv_raw` synchronously sends the entire frame before it begins receiving. The over-complexity fixture is 1,048,583 bytes including its length prefix. The local socket-pair send buffer reported 212,992 bytes; the send-before-read probe timed out, and the unmodified SEC-132 subprocess exceeded a five-second diagnostic deadline after its first three assertions. This is a real transport fixture deadlock, not a production parser failure. The earlier in-memory adaptation was diagnostic and did not count as a passing original test.

The original fixture now starts a bounded sender while the unmodified receiver drains the socket. Both sockets have ten-second I/O deadlines; the worker is joined and required to terminate on all paths. Successful receive propagates sender errors. All original SEC-132 parser-before-decode, frame-budget release, boundary/headroom, healthy handshake and chain-identity assertions remain intact. The repaired original test is executed directly and through the complete security-tail runner.

Five additional fixture regressions cover exact release/EOF/wrong byte, bounded missing-parent release, first-call-only delegation/restoration, a valid large frame over a deliberately small socket buffer, and an invalid large frame rejected before JSON parsing with zero remaining frame reservation. The full-validation registry includes these tests; no existing suite is removed.

## Integrity metadata and environment

`release_manifest.json` authenticates existing validation fixture source. Its hashes became stale when those fixtures changed; full validation correctly rejected the first edited checkpoint file. Seven test/harness entries are updated: checkpoint 51/52/53 daemon fixtures, SEC-132, the full runner, and the two new test-support/regression files. Every field outside `files`, and every other file entry, is unchanged. This is necessary tracked source-integrity metadata, not an activation or release-policy change. Raw timing JSON, binaries and execution logs are excluded from the commit.

The workspace is group-writable, so POSIX provenance contracts correctly reject it as a trusted release runtime. Security-tail execution uses an owner-only `/tmp/arch001-current-validation` tree created from main plus the exact edited/new source overlay, with source contents preserved. The isolated CPython 3.13.15 executable also has group/other write permission removed. Workspace permissions and production validators are unchanged. `umask 077` prevents test-created private files from being group-readable/writable. Hash-locked runtime dependencies match the existing CI locks.

## Commands and results

Run from `/home/axven/axven-core` unless a different working directory is specified. Interpreter: `/tmp/arch001-py313/bin/python`. Logs remain in `/tmp`; no generated logs or raw measurement artifacts are staged.

```sh
umask 077
/tmp/arch001-py313/bin/python validation_fixture_regression_test.py
/tmp/arch001-py313/bin/python checkpoint51_peer_health_transitions_daemon_spec.py
/tmp/arch001-py313/bin/python checkpoint52_peer_health_history_daemon_spec.py
/tmp/arch001-py313/bin/python checkpoint53_peer_health_incidents_daemon_spec.py
/tmp/arch001-py313/bin/python security_sec132_p2p_json_preparse_complexity_spec.py
/tmp/arch001-py313/bin/python research/programmable_l1/arch001_auth_timing_protocol_test.py
/tmp/arch001-py313/bin/python -O research/programmable_l1/arch001_auth_timing_protocol_test.py
/tmp/arch001-py313/bin/python research/programmable_l1/arch001_evidence_integration_test.py
/tmp/arch001-py313/bin/python research/programmable_l1/arch001_decision_bundle.py
/tmp/arch001-py313/bin/python run_full_validation.py
```

Security tail, with working directory `/tmp/arch001-current-validation`:

```sh
umask 077
/tmp/arch001-py313/bin/python security_tail_runner.py
```

Completed focused results: fixture regressions 5/5; checkpoint 51 14/14; checkpoint 52 13/13; checkpoint 53 24/24; original repaired SEC-132 14/14; timing regressions 8/8 normally and 8/8 with `-O`; evidence integration 3/3; canonical bundle 30/30 with the unchanged digest above; `pip check` has no broken requirements.

Final full-validation command (including output redirection):

```sh
umask 077
/tmp/arch001-py313/bin/python run_full_validation.py > /tmp/arch001-final-full-validation.log 2>&1
```

Result: exit 0, **99/99 suites pass**, including all original full-validation suites and the five new fixture regressions. Release packaging verifies **680/680** checks with the refreshed test-file manifest entries. No suite was skipped or assertion relaxed. Final security-tail command, with working directory `/tmp/arch001-current-validation`:

```sh
umask 077
/tmp/arch001-py313/bin/python security_tail_runner.py > /tmp/arch001-final-security-tail.log 2>&1
```

Result: exit 0, **156/156 original security-tail scripts pass in one complete run**, including the repaired original SEC-132 fixture. No temporary helper replacement or skipped script was used. This resolves the previous deadlock and permission-environment blockers for local validation.

Final canonical command:

```sh
/tmp/arch001-py313/bin/python research/programmable_l1/arch001_decision_bundle.py > /tmp/arch001-final-canonical-bundle.jsonl
```

Result: exit 0, **30/30 GREEN**, unchanged digest `e538952708f8a1ae59ef9d83022d8aabc413f641c0ff0118646751fd1d10879b`.

Final content review covers exactly 18 authored research/test/CI/integrity-metadata files. No pre-existing user changes, secrets, raw timing JSON, logs, build outputs or binaries are included. The nine inspected production/configuration/security-policy files (`axven.py`, `core.py`, `p2p.py`, `wallet.py`, `datadir.py`, `rpc.py`, `axven_core.py`, `runtime_provenance.py`, `pyproject.toml`) are byte-identical to main. Exact-head CI remains a remote gate until the pushed commit is checked; local passing results do not authorize merging. The initial release-packaging hash failure is retained as investigation evidence; only the final run can satisfy the gate. Exact-head CI and blocking-review inspection are required after commit/push. Nothing is merged or activated by this work.
