#!/usr/bin/env python3
"""RUST-150 fail-closed mutation selftest for CI fan-out policy."""
from __future__ import annotations

import rust_150_ci_fanout_policy_spec as policy


def reject(label: str, fn) -> None:
    try:
        fn()
    except AssertionError:
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def remove_pr_path(workflow: str, path_line: str) -> str:
    """Remove exactly one required path from the pull_request paths block only."""
    marker = "  pull_request:\n    paths:\n"
    if workflow.count(marker) != 1:
        raise AssertionError("unexpected pull_request paths block")
    before, after = workflow.split(marker, 1)
    next_top = after.find("\n  workflow_dispatch:")
    if next_top < 0:
        raise AssertionError("unexpected pull_request block boundary")
    pr_body, rest = after[:next_top], after[next_top:]
    needle = f"      - {path_line}\n"
    if pr_body.count(needle) != 1:
        raise AssertionError(f"expected one PR path entry: {path_line}")
    pr_body = pr_body.replace(needle, "", 1)
    return before + marker + pr_body + rest


def main() -> None:
    validation = policy.text(policy.VALIDATION)
    fuzz = policy.text(policy.FUZZ)
    perf = policy.text(policy.PERF)
    native = policy.text(policy.NATIVE)
    policy.check_texts(validation, fuzz, perf, native)

    cases = 0
    reject("validation-pull-request-removed", lambda: policy.check_texts(validation.replace("  pull_request:\n", "", 1), fuzz, perf, native)); cases += 1
    reject("validation-path-filter-added", lambda: policy.check_texts(validation.replace("  pull_request:\n", "  pull_request:\n    paths:\n      - 'axven/**'\n", 1), fuzz, perf, native)); cases += 1
    reject("fuzz-pull-request-removed", lambda: policy.check_texts(validation, fuzz.replace("  pull_request:\n", "", 1), perf, native)); cases += 1
    reject("fuzz-path-filter-added", lambda: policy.check_texts(validation, fuzz.replace("  pull_request:\n", "  pull_request:\n    paths:\n      - 'fuzz/**'\n", 1), perf, native)); cases += 1
    reject("performance-pr-removed", lambda: policy.check_texts(validation, fuzz, perf.replace("  pull_request:\n", "", 1), native)); cases += 1
    reject("performance-command-removed", lambda: policy.check_texts(validation, fuzz, perf.replace("python perf_001_baseline.py", "echo skipped"), native)); cases += 1
    reject("native-rust-source-trigger-removed", lambda: policy.check_texts(validation, fuzz, perf, remove_pr_path(native, '"rust_*.py"'))); cases += 1
    reject("native-doc-trigger-removed", lambda: policy.check_texts(validation, fuzz, perf, remove_pr_path(native, '"RUST_*.md"'))); cases += 1
    reject("native-predecessor-trigger-removed", lambda: policy.check_texts(validation, fuzz, perf, remove_pr_path(native, '".github/workflows/native-rust148-multistep-rust146-checkpoint-monitor-rotation.yml"'))); cases += 1
    reject("native-self-trigger-removed", lambda: policy.check_texts(validation, fuzz, perf, remove_pr_path(native, '".github/workflows/native-rust149-checkpoint-monitor-rotation-journal.yml"'))); cases += 1
    reject("validation-write-permission", lambda: policy.check_texts(validation.replace("contents: read", "contents: write"), fuzz, perf, native)); cases += 1
    reject("fuzz-persist-credentials", lambda: policy.check_texts(validation, fuzz.replace("persist-credentials: false", "persist-credentials: true"), perf, native)); cases += 1

    if cases != 12:
        raise AssertionError(f"unexpected RUST-150 mutation count: {cases}")
    print("RUST-150 CI fan-out fail-closed contract: 12/12 expected mutations rejected")


if __name__ == "__main__":
    main()
