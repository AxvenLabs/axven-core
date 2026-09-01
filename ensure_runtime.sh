#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

venv_python=".venv/bin/python"
digest_path=".venv/.axven-python.sha256"
if [[ ! -x "$venv_python" ]]; then
  echo "Axven validated POSIX runtime is missing; run: bash validate_linux_macos.sh" >&2
  exit 2
fi
if [[ ! -f "$digest_path" || -L "$digest_path" ]]; then
  echo "Axven runtime interpreter attestation is missing; remove .venv and rerun: bash validate_linux_macos.sh" >&2
  exit 2
fi
IFS= read -r expected_digest < "$digest_path" || true
if [[ ! "$expected_digest" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Axven runtime interpreter attestation is invalid" >&2
  exit 2
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual_digest="$(sha256sum -- "$venv_python" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_digest="$(shasum -a 256 -- "$venv_python" | awk '{print $1}')"
else
  echo "Axven runtime attestation requires sha256sum or shasum" >&2
  exit 2
fi
if [[ "$actual_digest" != "$expected_digest" ]]; then
  echo "Axven runtime interpreter attestation mismatch; remove .venv and rerun: bash validate_linux_macos.sh" >&2
  exit 2
fi

"$venv_python" runtime_provenance.py check
