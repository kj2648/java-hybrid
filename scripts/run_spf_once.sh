#!/usr/bin/env bash
set -euo pipefail

# Back-compat wrapper: run SPF once for a Jazzer-style launcher + seed.
#
# Preferred (hybrid):
#   python3 -m cli --work-dir WORK all --mode default --fuzzer-path /path/to/FuzzerLauncher
#
# Usage:
#   scripts/run_spf_once.sh --fuzzer-path /path/to/FuzzerLauncher --seed /path/to/seedfile [--out DIR] [--work-dir DIR]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FUZZER_PATH=""
SEED=""
OUT_DIR="$ROOT_DIR/work/spf_out"
WORK_DIR="$ROOT_DIR/work"

usage() {
  cat <<USAGE
Usage:
  scripts/run_spf_once.sh --fuzzer-path PATH --seed PATH [--out DIR] [--work-dir DIR]
USAGE
}

abspath() {
  python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fuzzer-path|--launcher)
      FUZZER_PATH="$2"; shift 2;;
    --seed)
      SEED="$2"; shift 2;;
    --out)
      OUT_DIR="$2"; shift 2;;
    --work-dir)
      WORK_DIR="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$FUZZER_PATH" || -z "$SEED" ]]; then
  usage
  exit 2
fi

FUZZER_PATH="$(abspath "$FUZZER_PATH")"
SEED="$(abspath "$SEED")"
OUT_DIR="$(abspath "$OUT_DIR")"
WORK_DIR="$(abspath "$WORK_DIR")"

mkdir -p "$OUT_DIR"
exec python3 "$ROOT_DIR/engines/spf_engine.py" --fuzzer-path "$FUZZER_PATH" --work-dir "$WORK_DIR" "$SEED" "$OUT_DIR"
