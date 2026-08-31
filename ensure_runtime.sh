#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

venv_python=".venv/bin/python"

runtime_green() {
  [[ -x "$venv_python" ]] || return 1
  "$venv_python" runtime_provenance.py check >/dev/null 2>&1 || return 1
  "$venv_python" doctor.py >/dev/null 2>&1 || return 1
}

if ! runtime_green; then
  echo "Axven runtime is missing, stale, or unvalidated; running hardened validation..." >&2
  bash validate_linux_macos.sh
fi

if ! runtime_green; then
  echo "Axven runtime provenance validation failed" >&2
  exit 2
fi

echo "Axven runtime provenance: GREEN"
