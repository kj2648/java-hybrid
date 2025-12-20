#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-java-hybrid-spf}"
DOCKERFILE="${DOCKERFILE:-$ROOT_DIR/docker/Dockerfile.spf}"

usage() {
  cat <<'USAGE'
spf_docker.sh: Build/run a JDK8+Ant environment for SPF (jpf-core/jpf-symbc).

Usage:
  scripts/spf_docker.sh build
  scripts/spf_docker.sh shell
  scripts/spf_docker.sh setup
  scripts/spf_docker.sh run --corpus /path/to/corpus [--mode default|atl] [--backend spf] [--workers N] --fuzzer-path /path/to/FuzzerLauncher
  scripts/spf_docker.sh run-once --fuzzer-path /path/to/FuzzerLauncher --seed /path/to/seedfile [--out work/spf_out]

Notes:
  - The repo is mounted into /workspace.
  - setup clones/builds into third_party/spf inside the workspace.
  - You still need network access for cloning (either during setup or beforehand).
USAGE
}

need_docker() {
  command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 2; }
}

docker_run() {
  local cmd=("$@")
  mkdir -p "$ROOT_DIR/.home"
  need_docker

  docker run --rm -it \
    --user "$(id -u):$(id -g)" \
    -e HOME=/workspace/.home \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace \
    "$IMAGE_NAME" \
    "${cmd[@]}"
}

abspath() {
  python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$1"
}

case "${1:-}" in
  build)
    need_docker
    docker build -t "$IMAGE_NAME" -f "$DOCKERFILE" "$ROOT_DIR"
    ;;
  shell)
    docker_run bash
    ;;
  setup)
    docker_run bash -lc "scripts/setup_spf.sh"
    ;;
  run)
    shift
    CORPUS=""
    MODE="atl"
    BACKEND="spf"
    WORKERS="1"
    FUZZER_PATH=""

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --corpus)
          CORPUS="$2"
          shift 2
          ;;
        --mode)
          MODE="$2"
          shift 2
          ;;
        --backend)
          BACKEND="$2"
          shift 2
          ;;
        --workers)
          WORKERS="$2"
          shift 2
          ;;
        --fuzzer-path)
          FUZZER_PATH="$2"
          shift 2
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

    if [[ -z "$CORPUS" ]]; then
      echo "--corpus is required" >&2
      usage
      exit 2
    fi
    if [[ "$BACKEND" == "spf" && -z "$FUZZER_PATH" ]]; then
      echo "--fuzzer-path is required when --backend=spf" >&2
      usage
      exit 2
    fi

    CORPUS_HOST="$(abspath "$CORPUS")"
    if [[ ! -d "$CORPUS_HOST" ]]; then
      echo "Corpus dir not found: $CORPUS_HOST" >&2
      exit 2
    fi

    # Use the generated env file if it exists.
    mkdir -p "$ROOT_DIR/.home"
    need_docker
    docker run --rm -it \
      --user "$(id -u):$(id -g)" \
      -e HOME=/workspace/.home \
      -v "$ROOT_DIR:/workspace" \
      -v "$CORPUS_HOST:/workspace/work/corpus" \
      -w /workspace \
      "$IMAGE_NAME" \
      bash -lc "\
      if [[ -f scripts/spf_env.sh ]]; then source scripts/spf_env.sh; fi; \
      python3 -m cli --work-dir work all --mode \"$MODE\" --no-router --no-fuzzer --no-watcher --dse-backend \"$BACKEND\" --dse-workers \"$WORKERS\" --fuzzer-path \"$FUZZER_PATH\" \
    "
    ;;
  run-once)
    shift
    LAUNCHER=""
    SEED=""
    OUT_DIR="/workspace/work/spf_out"

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --fuzzer-path|--launcher)
          LAUNCHER="$2"; shift 2;;
        --seed)
          SEED="$2"; shift 2;;
        --out)
          OUT_DIR="$2"; shift 2;;
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

    if [[ -z "$LAUNCHER" ]]; then
      echo "--fuzzer-path is required" >&2
      usage
      exit 2
    fi
    if [[ -z "$SEED" ]]; then
      echo "--seed is required" >&2
      usage
      exit 2
    fi

    LAUNCHER_HOST="$(abspath "$LAUNCHER")"
    SEED_HOST="$(abspath "$SEED")"
    if [[ ! -f "$LAUNCHER_HOST" ]]; then
      echo "Launcher file not found: $LAUNCHER_HOST" >&2
      exit 2
    fi
    if [[ ! -f "$SEED_HOST" ]]; then
      echo "Seed file not found: $SEED_HOST" >&2
      exit 2
    fi

    LAUNCHER_DIR_HOST="$(dirname "$LAUNCHER_HOST")"
    LAUNCHER_BASE="$(basename "$LAUNCHER_HOST")"

    mkdir -p "$ROOT_DIR/.home"
    need_docker
    docker run --rm -it \
      --user "$(id -u):$(id -g)" \
      -e HOME=/workspace/.home \
      -v "$ROOT_DIR:/workspace" \
      -v "$LAUNCHER_DIR_HOST:/mnt/fuzzer_out:ro" \
      -v "$SEED_HOST:/mnt/seed:ro" \
      -w /workspace \
      "$IMAGE_NAME" \
      bash -lc "\
        scripts/run_spf_once.sh --launcher \"/mnt/fuzzer_out/$LAUNCHER_BASE\" --seed /mnt/seed --out \"$OUT_DIR\" \
      "
    ;;
  *)
    usage
    exit 2
    ;;
esac
