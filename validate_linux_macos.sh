#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

required_python="3.13.15"
actual_python="$(python3 -c 'import platform; print(platform.python_version())')"
if [[ "$actual_python" != "$required_python" ]]; then
  echo "Axven validation requires exact Python $required_python; found $actual_python" >&2
  exit 2
fi

os="$(uname -s)"
arch="$(uname -m)"
case "$os:$arch" in
  Linux:x86_64|Linux:aarch64|Linux:arm64|Darwin:arm64)
    ;;
  *)
    echo "unsupported POSIX validation platform: $os/$arch" >&2
    exit 2
    ;;
esac

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

venv_python=".venv/bin/python"
if [[ ! -x "$venv_python" ]]; then
  echo "existing .venv has no executable Python; remove it and rerun" >&2
  exit 2
fi

venv_version="$($venv_python -c 'import platform; print(platform.python_version())')"
if [[ "$venv_version" != "$required_python" ]]; then
  echo "existing .venv is not Python $required_python; remove it and rerun" >&2
  exit 2
fi

"$venv_python" -m pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-toolchain.lock
"$venv_python" -m pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-runtime-posix.lock
"$venv_python" -m pip install --no-build-isolation --no-deps -e ".[legacy-mldsa-recovery]"
"$venv_python" -m pip check

printf '\n=== AXVEN DOCTOR ===\n'
"$venv_python" doctor.py

printf '\n=== FULL VALIDATION ===\n'
"$venv_python" run_full_validation.py

printf '\n=== SEC-076+ SECURITY TAIL ===\n'
"$venv_python" security_tail_runner.py

echo "ALL AXVEN CHECKS GREEN"
