#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ -L .venv ]]; then
  echo "Axven validated runtime directory must not be a symlink; remove .venv and rerun validation" >&2
  exit 2
fi
if [[ -e .venv && ! -d .venv ]]; then
  echo "Axven validated runtime path is not a directory; remove .venv and rerun validation" >&2
  exit 2
fi

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

created_venv=0
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  created_venv=1
fi

venv_python=".venv/bin/python"
digest_path=".venv/.axven-python.sha256"
verifier_path="runtime_provenance.py"
verifier_digest_path=".venv/.axven-runtime-provenance.sha256"
if [[ ! -x "$venv_python" ]]; then
  echo "existing .venv has no executable Python; remove it and rerun" >&2
  exit 2
fi
if [[ "$created_venv" -eq 0 ]]; then
  if [[ ! -f "$digest_path" || -L "$digest_path" ]]; then
    echo "existing .venv lacks interpreter attestation; remove it and rerun" >&2
    exit 2
  fi
  IFS= read -r expected_digest < "$digest_path" || true
  if [[ ! "$expected_digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "existing .venv interpreter attestation is invalid; remove it and rerun" >&2
    exit 2
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual_digest="$(sha256sum -- "$venv_python" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual_digest="$(shasum -a 256 -- "$venv_python" | awk '{print $1}')"
  else
    echo "Axven validation requires sha256sum or shasum" >&2
    exit 2
  fi
  if [[ "$actual_digest" != "$expected_digest" ]]; then
    echo "existing .venv interpreter attestation mismatch; remove it and rerun" >&2
    exit 2
  fi
  if [[ ! -f "$verifier_path" || -L "$verifier_path" || ! -f "$verifier_digest_path" || -L "$verifier_digest_path" ]]; then
    echo "existing .venv lacks provenance verifier attestation; remove it and rerun" >&2
    exit 2
  fi
  IFS= read -r expected_verifier_digest < "$verifier_digest_path" || true
  if [[ ! "$expected_verifier_digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "existing .venv provenance verifier attestation is invalid; remove it and rerun" >&2
    exit 2
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual_verifier_digest="$(sha256sum -- "$verifier_path" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual_verifier_digest="$(shasum -a 256 -- "$verifier_path" | awk '{print $1}')"
  else
    echo "Axven validation requires sha256sum or shasum" >&2
    exit 2
  fi
  if [[ "$actual_verifier_digest" != "$expected_verifier_digest" ]]; then
    echo "existing .venv provenance verifier attestation mismatch; remove it and rerun" >&2
    exit 2
  fi
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

printf '\n=== RUNTIME PROVENANCE RECEIPT ===\n'
"$venv_python" runtime_provenance.py stamp

echo "ALL AXVEN CHECKS GREEN"
