#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

venv_python=".venv/bin/python"
if [[ ! -x "$venv_python" ]]; then
  echo "Axven validated POSIX runtime is missing; run: bash validate_linux_macos.sh" >&2
  exit 2
fi

"$venv_python" runtime_provenance.py check
