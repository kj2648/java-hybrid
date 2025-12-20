#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-"$ROOT_DIR/third_party/spf"}"
UPDATE=0
SKIP_BUILD=0
JAVA_HOME_OVERRIDE=""
JPF_CORE_REF="${JPF_CORE_REF:-java-8}"
JPF_SYMBC_REF="${JPF_SYMBC_REF:-master}"

usage() {
  cat <<'USAGE'
setup_spf.sh: Clone + build SPF dependencies (jpf-core, jpf-symbc).

Usage:
  scripts/setup_spf.sh [--dir PATH] [--update] [--skip-build] [--java-home PATH] [--jpf-core-ref REF] [--jpf-symbc-ref REF]

Outputs:
  - third_party/spf/jpf-core
  - third_party/spf/jpf-symbc
  - scripts/spf_env.sh (exports you can source)

Notes:
  - Requires: git, ant, java
  - jpf-core has multiple lines:
      - master: module-patching build (JDK/version sensitive)
      - java-8: legacy line (often easier for JDK8-based targets)
  - jpf-symbc tests are disabled by default (set SPF_BUILD_TESTS=1 to compile them).
  - Network access required for git clone.
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
    --java-home)
      JAVA_HOME_OVERRIDE="$2"
      shift 2
      ;;
    --jpf-core-ref)
      JPF_CORE_REF="$2"
      shift 2
      ;;
    --jpf-symbc-ref)
      JPF_SYMBC_REF="$2"
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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }
}

need_cmd git
need_cmd java
need_cmd ant

if [[ -n "$JAVA_HOME_OVERRIDE" ]]; then
  export JAVA_HOME="$JAVA_HOME_OVERRIDE"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

# Keep Gradle state inside the workspace (some environments block ~/.gradle writes).
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-"$INSTALL_DIR/.gradle"}"

echo "[setup_spf] using java:"
java -version 2>&1 | sed 's/^/[setup_spf]   /'
if [[ -n "${JAVA_HOME:-}" ]]; then
  echo "[setup_spf] JAVA_HOME=$JAVA_HOME"
fi
echo "[setup_spf] GRADLE_USER_HOME=$GRADLE_USER_HOME"

JAVA_MAJOR="$(java -version 2>&1 | awk -F'[\".]' '/version/ {print $2; exit}')"
if [[ -n "$JAVA_MAJOR" ]] && [[ "$JAVA_MAJOR" -ne 8 ]]; then
  echo "[setup_spf] WARNING: Java $JAVA_MAJOR detected; this workflow is standardized on JDK8." >&2
  echo "[setup_spf]          If the build fails, use JDK8 (or run inside docker/Dockerfile.spf)." >&2
fi

mkdir -p "$INSTALL_DIR"

clone_or_update() {
  local repo="$1"
  local dir="$2"
  local ref="${3:-master}"

  ensure_full_history() {
    local d="$1"
    if [[ -f "$d/.git/shallow" ]]; then
      echo "[setup_spf] unshallowing $d (required for git-version plugin)"
      git -C "$d" fetch --unshallow --tags
    fi
  }

  if [[ -d "$dir/.git" ]]; then
    # Always ensure the requested ref is checked out (even without --update)
    git -C "$dir" fetch --all --tags
    if [[ -n "$ref" ]]; then
      git -C "$dir" checkout "$ref" >/dev/null 2>&1 || true
    fi
    ensure_full_history "$dir"

    if [[ "$UPDATE" -eq 1 ]]; then
      echo "[setup_spf] updating $dir"
      git -C "$dir" pull --ff-only
    else
      echo "[setup_spf] exists $dir (use --update to pull)"
    fi
    return 0
  fi

  echo "[setup_spf] cloning $repo -> $dir"
  if [[ -n "$ref" ]]; then
    # Full history is required for the gradle git-version plugin used by jpf-core.
    git clone --branch "$ref" "$repo" "$dir"
  else
    git clone "$repo" "$dir"
  fi
}

JPF_CORE_DIR="$INSTALL_DIR/jpf-core"
JPF_SYMBC_DIR="$INSTALL_DIR/jpf-symbc"
SITE_PROPS="$INSTALL_DIR/site.properties"

clone_or_update "https://github.com/javapathfinder/jpf-core.git" "$JPF_CORE_DIR" "$JPF_CORE_REF"
clone_or_update "https://github.com/SymbolicPathFinder/jpf-symbc.git" "$JPF_SYMBC_DIR" "$JPF_SYMBC_REF"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
build_project() {
  local dir="$1"
  local name="$2"
  echo "[setup_spf] building $name"
  if [[ -f "$dir/build.xml" ]]; then
    (cd "$dir" && ant clean build)
    return 0
  fi
  if [[ -x "$dir/gradlew" ]]; then
    # jpf-core(java-8) needs these artifacts for jpf-symbc ant build:
    #   build/jpf.jar, build/jpf-annotations.jar, build/jpf-classes.jar, build/RunJPF.jar, build/asm-*.jar
    (cd "$dir" && ./gradlew --no-daemon clean createJpfJar createJpfClassesJar createAnnotationsJar createRunJpfJar)
    return 0
  fi
  if [[ -f "$dir/build.gradle" ]]; then
    echo "[setup_spf] $name uses Gradle but gradlew is missing: $dir" >&2
    return 1
  fi
  echo "[setup_spf] missing build file in $dir (expected build.xml or gradlew)" >&2
  return 1
}

prepare_jpf_symbc_tree() {
  local symbc_dir="$1"

  # jpf-symbc's Ant build tries to compile tests if src/tests exists, but many environments
  # don't have JUnit on the classpath. For the SPF engine workflow we don't need these tests,
  # so disable them by default (set SPF_BUILD_TESTS=1 to keep them).
  if [[ "${SPF_BUILD_TESTS:-0}" != "1" ]] && [[ -d "$symbc_dir/src/tests" ]]; then
    echo "[setup_spf] disabling jpf-symbc tests (set SPF_BUILD_TESTS=1 to keep)"
    mv "$symbc_dir/src/tests" "$symbc_dir/src/tests.disabled"
  fi

  # If tests are enabled, try to ensure JUnit is available via lib/*.jar.
  if [[ "${SPF_BUILD_TESTS:-0}" == "1" ]] && [[ -d "$symbc_dir/src/tests" ]]; then
    local have_junit=0
    if ls "$symbc_dir/lib"/junit*.jar >/dev/null 2>&1; then
      have_junit=1
    fi
    if [[ "$have_junit" -eq 0 ]]; then
      local candidates=(
        "${JUNIT_JAR:-}"
        "/usr/share/java/junit4.jar"
        "/usr/share/java/junit.jar"
        "/usr/share/java/junit4-4.13.2.jar"
        "/usr/share/java/junit-4.13.2.jar"
      )
      for c in "${candidates[@]}"; do
        if [[ -n "$c" ]] && [[ -f "$c" ]]; then
          echo "[setup_spf] copying JUnit jar into jpf-symbc/lib: $c"
          cp -f "$c" "$symbc_dir/lib/$(basename "$c")"
          have_junit=1
          break
        fi
      done
    fi
    if [[ "$have_junit" -eq 0 ]]; then
      echo "[setup_spf] ERROR: SPF_BUILD_TESTS=1 but no JUnit jar found (set JUNIT_JAR or install junit4)" >&2
      return 1
    fi
  fi
}

ensure_jpf_core_jars() {
  local core_dir="$1"
  local build_dir="$core_dir/build"

  if [[ ! -d "$build_dir" ]]; then
    echo "[setup_spf] ERROR: missing $build_dir (jpf-core build did not produce outputs)" >&2
    return 1
  fi

  if ! command -v jar >/dev/null 2>&1; then
    echo "[setup_spf] ERROR: 'jar' tool not found (JDK required)" >&2
    return 1
  fi

  # Gradle should create these via createJpfJar/createJpfClassesJar/createAnnotationsJar, but keep a
  # fallback because some environments end up with only RunJPF.jar created.
  if [[ ! -f "$build_dir/jpf-annotations.jar" ]]; then
    if [[ -d "$build_dir/annotations" ]]; then
      echo "[setup_spf] creating jpf-annotations.jar (fallback)"
      (cd "$build_dir" && jar cf jpf-annotations.jar -C annotations .)
    fi
  fi

  if [[ ! -f "$build_dir/jpf.jar" ]]; then
    if [[ -d "$build_dir/main" ]] && [[ -d "$build_dir/peers" ]] && [[ -d "$build_dir/annotations" ]]; then
      echo "[setup_spf] creating jpf.jar (fallback)"
      (cd "$build_dir" && jar cf jpf.jar -C main . -C peers . -C annotations .)
      if [[ -d "$build_dir/classes/org/junit" ]]; then
        (cd "$build_dir" && jar uf jpf.jar -C classes org/junit)
      fi
    fi
  fi

  if [[ ! -f "$build_dir/jpf-classes.jar" ]]; then
    if [[ -d "$build_dir/classes" ]] && [[ -d "$build_dir/annotations" ]]; then
      echo "[setup_spf] creating jpf-classes.jar (fallback)"
      (cd "$build_dir" && jar cf jpf-classes.jar -C classes . -C annotations .)
      local required_from_main=(
        "gov/nasa/jpf/JPFShell.class"
        "gov/nasa/jpf/vm/Verify.class"
        "gov/nasa/jpf/util/TypeRef.class"
        "gov/nasa/jpf/util/test/TestJPF.class"
        "gov/nasa/jpf/util/test/TestMultiProcessJPF.class"
        "gov/nasa/jpf/util/test/TestJPFHelper.class"
      )
      for rel in "${required_from_main[@]}"; do
        if [[ -f "$build_dir/main/$rel" ]]; then
          (cd "$build_dir" && jar uf jpf-classes.jar -C main "$rel")
        fi
      done
    fi
  fi
}

echo "[setup_spf] building jpf-core"
build_project "$JPF_CORE_DIR" "jpf-core"
ensure_jpf_core_jars "$JPF_CORE_DIR"
missing_core=()
for f in build/RunJPF.jar build/jpf.jar build/jpf-annotations.jar build/jpf-classes.jar; do
  if [[ ! -f "$JPF_CORE_DIR/$f" ]]; then
    missing_core+=("$f")
  fi
done
if [[ "${#missing_core[@]}" -ne 0 ]]; then
  echo "[setup_spf] ERROR: jpf-core build missing artifacts:" >&2
  for f in "${missing_core[@]}"; do
    echo "[setup_spf]   - $JPF_CORE_DIR/$f" >&2
  done
  exit 1
fi

echo "[setup_spf] building jpf-symbc"
prepare_jpf_symbc_tree "$JPF_SYMBC_DIR"
build_project "$JPF_SYMBC_DIR" "jpf-symbc"
else
  echo "[setup_spf] skip build (--skip-build)"
fi

# Generate a local site.properties so RunJPF.jar can resolve extensions (jpf-symbc).
cat > "$SITE_PROPS" <<EOF
# auto-generated by scripts/setup_spf.sh

# Use config_path for portability (this file lives under third_party/spf/).
jpf-core = \${config_path}/jpf-core
jpf-symbc = \${config_path}/jpf-symbc

# Load these projects during startup (so SymbolicListener resolves).
extensions=\${jpf-core},\${jpf-symbc}
EOF

ENV_OUT="$ROOT_DIR/scripts/spf_env.sh"
cat > "$ENV_OUT" <<EOF
#!/usr/bin/env bash
# Source this file before running SPF backend.
#   source scripts/spf_env.sh

ROOT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"

export JPF_HOME="\${JPF_HOME:-"\$ROOT_DIR/third_party/spf/jpf-core"}"
export JPF_SYMBC="\${JPF_SYMBC:-"\$ROOT_DIR/third_party/spf/jpf-symbc"}"
export SPF_SITE="\${SPF_SITE:-"\$ROOT_DIR/third_party/spf/site.properties"}"

# Required for engines/spf_engine.py
export SPF_TARGET="\${SPF_TARGET:-com.example.Main}"
export SPF_CLASSPATH="\${SPF_CLASSPATH:-/abs/path/to/your/classes:/abs/path/to/deps.jar}"

# Optional tuning
export SPF_TEMPLATE="\${SPF_TEMPLATE:-$ROOT_DIR/templates/spf_run.jpf.tpl}"
export SPF_JAVA="\${SPF_JAVA:-java}"
export SPF_JVM_OPTS="\${SPF_JVM_OPTS:--Xmx2g}"
export SPF_TIME_BUDGET="\${SPF_TIME_BUDGET:-30}"
export SPF_MAX_OUTPUTS="\${SPF_MAX_OUTPUTS:-50}"
export SPF_MAX_LEN="\${SPF_MAX_LEN:-4096}"
EOF
chmod +x "$ENV_OUT"

cat <<EOF
[setup_spf] done

Next:
  1) Edit these two lines in scripts/spf_env.sh:
       SPF_TARGET=...
       SPF_CLASSPATH=...
  2) source scripts/spf_env.sh
  3) Run orchestrator:
       python3 -m cli --work-dir work all --mode default --fuzzer-path /path/to/FuzzerLauncher

Notes:
  - jpf-symbc tests are disabled by default; set SPF_BUILD_TESTS=1 to compile them.
EOF
