#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-"$ROOT_DIR/third_party/gdart"}"
UPDATE=0
SKIP_BUILD=0
REF="${GDART_REF:-}"
RUN_TESTS=0

usage() {
  cat <<'USAGE'
setup_gdart.sh: Clone + build GDART (SPouT + solver backend).

Usage:
  scripts/setup_gdart.sh [--dir PATH] [--update] [--skip-build] [--ref REF] [--run-tests]

Outputs:
  - third_party/gdart (default)
  - scripts/gdart_env.sh (optional helper to export GDART_HOME)

Notes:
  - Requires: git (and whatever GDART's ./build.sh requires)
  - Network access required for git clone.
  - By default, tests are skipped to avoid JDK/module-policy flakiness; pass --run-tests to enable them.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --update)
      UPDATE=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --ref)
      REF="$2"
      shift 2
      ;;
    --run-tests)
      RUN_TESTS=1
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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }
}

need_cmd git
need_cmd mvn

GDART_DIR="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$INSTALL_DIR")"

ensure_pipes_shim() {
  # GDART's mx-based build (SPouT/GraalVM suites) imports stdlib `pipes`, which was removed in Python 3.13.
  # Provide a tiny shim so the build works with newer system Pythons.
  if python3 -c 'import pipes' >/dev/null 2>&1; then
    return 0
  fi
  local shim_dir="$GDART_DIR/mx"
  local shim="$shim_dir/pipes.py"
  mkdir -p "$shim_dir"
  cat >"$shim" <<'PY'
"""
Compatibility shim for Python 3.13+ where stdlib `pipes` was removed.
Only `pipes.quote` is used by mx suites; delegate to `shlex.quote`.
"""
from shlex import quote  # noqa: F401

__all__ = ["quote"]
PY
  echo "[setup_gdart] wrote Python 3.13+ shim: $shim"
}

build_gdart() {
  local mvn_flags=()
  if [[ "$RUN_TESTS" -eq 0 ]]; then
    mvn_flags+=("-DskipTests")
  fi

  git submodule update --init

  # SPouT / GraalVM build.
  # `yes | ...` is used upstream; with `set -o pipefail` the `yes` SIGPIPE can fail the pipeline
  # even when mx succeeds, so disable pipefail for this single pipeline.
  set +o pipefail
  yes | ./mx/mx fetch-jdk --jdk-id labsjdk-ce-17 --strip-contents-home --to .
  set -o pipefail
  pushd SPouT/espresso >/dev/null
    ../../mx/mx --env native-ce --java-home ../../labsjdk-ce-17-jvmci-23.0-b01 build
  popd >/dev/null

  local gvm
  gvm="$(find SPouT/sdk/mxbuild -name "GRAALVM_ESPRESSO_NATIVE_CE_JAVA17" -type d | head -n 1)"
  if [[ -z "$gvm" ]]; then
    echo "[setup_gdart] ERROR: failed to locate built GraalVM under SPouT/sdk/mxbuild" >&2
    return 1
  fi
  local gvm_bin
  gvm_bin="$(find "$gvm" -name "bin" -type d | head -n 1)"
  if [[ -z "$gvm_bin" ]]; then
    echo "[setup_gdart] ERROR: failed to locate GraalVM bin dir under: $gvm" >&2
    return 1
  fi

  {
    echo "#!/bin/bash"
    echo "GRAALVM_HOME=$gvm_bin"
  } > ./config

  # DSE
  pushd dse >/dev/null
    rm -Rf jconstraints
    ./compile-jconstraints.sh
    mvn "${mvn_flags[@]}" package
  popd >/dev/null

  # Verifier Stub
  pushd verifier-stub >/dev/null
    mvn "${mvn_flags[@]}" package
  popd >/dev/null
}

if [[ -d "$GDART_DIR/.git" ]]; then
  echo "[setup_gdart] already cloned: $GDART_DIR"
  if [[ "$UPDATE" -eq 1 ]]; then
    echo "[setup_gdart] updating..."
    git -C "$GDART_DIR" fetch --all --tags
    if [[ -n "$REF" ]]; then
      git -C "$GDART_DIR" checkout "$REF" >/dev/null 2>&1 || true
    fi
    git -C "$GDART_DIR" pull --ff-only || true
    git -C "$GDART_DIR" submodule update --init --recursive
  fi
else
  mkdir -p "$(dirname "$GDART_DIR")"
  echo "[setup_gdart] cloning into: $GDART_DIR"
  if [[ -n "$REF" ]]; then
    git clone --recursive --branch "$REF" https://github.com/tudo-aqua/gdart.git "$GDART_DIR"
  else
    git clone --recursive https://github.com/tudo-aqua/gdart.git "$GDART_DIR"
  fi
fi

# Ensure mx suites work on Python 3.13+ even if the user only wants to clone/update.
ensure_pipes_shim

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "[setup_gdart] building (this can take a while)..."
  (cd "$GDART_DIR" && build_gdart)
else
  echo "[setup_gdart] skip build (--skip-build)"
fi

echo "[setup_gdart] done"
echo "export GDART_HOME=\"$GDART_DIR\""

ENV_OUT="$ROOT_DIR/scripts/gdart_env.sh"
cat >"$ENV_OUT" <<EOF
#!/usr/bin/env bash
export GDART_HOME="$GDART_DIR"
EOF
chmod +x "$ENV_OUT"
echo "[setup_gdart] wrote $ENV_OUT"
