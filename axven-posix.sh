#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ $# -lt 1 ]]; then
  echo "usage: bash axven-posix.sh {core|cli|console|doctor} [args...]" >&2
  exit 2
fi

command_name="$1"
shift
case "$command_name" in
  core)
    target="axven_core.py"
    ;;
  cli)
    target="axven_cli.py"
    ;;
  console)
    target="axven_console.py"
    ;;
  doctor)
    target="doctor.py"
    ;;
  *)
    echo "unsupported Axven POSIX operator command: $command_name" >&2
    exit 2
    ;;
esac

# SEC-219: every supported POSIX operator command must prove that the exact
# .venv runtime was produced by the complete hardened validator before the
# first operator Python process is started.
bash ./ensure_runtime.sh
exec .venv/bin/python "$target" "$@"
