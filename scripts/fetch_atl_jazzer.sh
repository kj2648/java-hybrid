#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

INSTALL_DIR="${INSTALL_DIR:-"$ROOT_DIR/third_party/atl-jazzer"}"
REPO_URL="${REPO_URL:-https://github.com/Team-Atlanta/aixcc-afc-atlantis.git}"
REPO_REF="${REPO_REF:-main}"
BUILD=0

ATL_JAZZER_SUBDIR="example-crs-webservice/crs-java/crs/fuzzers/atl-jazzer"

usage() {
  cat <<'USAGE'
fetch_atl_jazzer.sh: Fetch only the atl-jazzer subtree (sparse checkout) into third_party/.

Usage:
  scripts/fetch_atl_jazzer.sh [--dir PATH] [--repo URL] [--ref REF] [--build]

Defaults:
  --dir  third_party/atl-jazzer
  --repo https://github.com/Team-Atlanta/aixcc-afc-atlantis.git
  --ref  main

Notes:
  - Requires: git
  - If you pass --build: requires bazelisk (or bazel) and a working toolchain.
  - Network access required.
USAGE
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --repo)
      REPO_URL="$2"
      shift 2
      ;;
    --ref)
      REPO_REF="$2"
      shift 2
      ;;
    --build)
      BUILD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

need_cmd git
if [[ "$BUILD" -eq 1 ]]; then
  if command -v bazelisk >/dev/null 2>&1; then
    :
  elif command -v bazel >/dev/null 2>&1; then
    :
  else
    echo "Missing required command for --build: bazelisk (or bazel)" >&2
    exit 2
  fi
fi

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

echo "[atl-jazzer] cloning (sparse) $REPO_URL@$REPO_REF"
git clone --depth 1 --filter=blob:none --sparse --branch "$REPO_REF" "$REPO_URL" "$tmp/repo" >/dev/null
git -C "$tmp/repo" sparse-checkout set "$ATL_JAZZER_SUBDIR" >/dev/null

src="$tmp/repo/$ATL_JAZZER_SUBDIR"
if [[ ! -d "$src" ]]; then
  echo "[atl-jazzer] ERROR: expected subtree not found: $ATL_JAZZER_SUBDIR" >&2
  exit 2
fi

echo "[atl-jazzer] installing -> $INSTALL_DIR"
rm -rf "$INSTALL_DIR"
mkdir -p "$(dirname "$INSTALL_DIR")"
cp -a "$src" "$INSTALL_DIR"

if [[ "$BUILD" -eq 1 ]]; then
  echo "[atl-jazzer] building (this may take a while on first run)"
  if command -v bazelisk >/dev/null 2>&1; then
    (cd "$INSTALL_DIR" && bazelisk build //:jazzer)
  else
    (cd "$INSTALL_DIR" && bazel build //:jazzer)
  fi
fi

echo "[atl-jazzer] done"
