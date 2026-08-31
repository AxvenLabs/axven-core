#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

required_python="3.13.15"
actual_python="$(python3 -I -S -c 'import platform; print(platform.python_version())')"
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

# SEC-219: never trust a stale virtualenv during hardened validation. Remove a
# symlink as a link; rebuild ordinary generated .venv directories from scratch.
if [[ -L .venv ]]; then
  rm -- .venv
elif [[ -e .venv ]]; then
  if [[ ! -d .venv ]]; then
    echo ".venv exists but is not a removable virtualenv directory" >&2
    exit 2
  fi
  rm -rf -- .venv
fi

python3 -I -S -m venv .venv

venv_python=".venv/bin/python"
if [[ ! -x "$venv_python" ]]; then
  echo "fresh .venv has no executable Python" >&2
  exit 2
fi

venv_version="$($venv_python -I -S -c 'import platform; print(platform.python_version())')"
if [[ "$venv_version" != "$required_python" ]]; then
  echo "fresh .venv is not Python $required_python" >&2
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

printf '\n=== RUNTIME PROVENANCE RECEIPT ===\n'
"$venv_python" runtime_provenance.py stamp

echo "ALL AXVEN CHECKS GREEN"
