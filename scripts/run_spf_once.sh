#!/usr/bin/env bash
set -euo pipefail

# Run SPF once for a Jazzer-style OSS-Fuzz launcher script/binary.
#
# Requirements:
#  - SPF deps installed via: scripts/setup_spf.sh (generates scripts/spf_env.sh)
#
# Usage:
#   scripts/run_spf_once.sh --launcher /path/to/fuzzer --seed /path/to/seedfile [--out work/spf_out]
#
# Env (optional):
#   - SPF_SYMBOLIC_ARRAYS=true|false  (default: true)
#   - SPF_USE_SYMBOLIC_LISTENER=1     (enables SymbolicListener; may be noisy for byte[] targets)
#   - SPF_SEED_MAX_BYTES=4096         (max seed bytes embedded into harness)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LAUNCHER=""
SEED=""
OUT_DIR="$ROOT_DIR/work/spf_out"

usage() {
  cat <<USAGE
Usage:
  scripts/run_spf_once.sh --launcher PATH --seed PATH [--out DIR]
USAGE
}

abspath() {
  python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --launcher)
      LAUNCHER="$2"; shift 2;;
    --seed)
      SEED="$2"; shift 2;;
    --out)
      OUT_DIR="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$LAUNCHER" ]]; then
  echo "--launcher is required" >&2
  exit 2
fi
if [[ -z "$SEED" ]]; then
  echo "--seed is required" >&2
  exit 2
fi

LAUNCHER="$(abspath "$LAUNCHER")"
SEED="$(abspath "$SEED")"
OUT_DIR="$(abspath "$OUT_DIR")"

if [[ ! -f "$LAUNCHER" ]]; then
  echo "Missing fuzzer launcher: $LAUNCHER" >&2
  exit 2
fi
if [[ ! -f "$SEED" ]]; then
  echo "Missing seed: $SEED" >&2
  exit 2
fi

if [[ ! -f "$ROOT_DIR/scripts/spf_env.sh" ]]; then
  echo "Missing SPF env file: $ROOT_DIR/scripts/spf_env.sh" >&2
  echo "Run: scripts/setup_spf.sh" >&2
  exit 2
fi

this_dir="$(cd "$(dirname "$LAUNCHER")" && pwd)"
fuzzer_name="$(basename "$LAUNCHER")"
safe_name="$(python3 - <<'PY' "$fuzzer_name"
import re,sys
print(re.sub(r'[^A-Za-z0-9_.-]+', '_', sys.argv[1]))
PY
)"

# Extract --cp=... and --target_class=... from the launcher (jazzer_driver invocation line).
read -r cp_arg target_class < <(
  python3 - <<'PY' "$LAUNCHER"
import re, sys
path = sys.argv[1]
txt = open(path, "r", encoding="utf-8", errors="replace").read()
cp = re.search(r"--cp=([^ \n]+)", txt)
tc = re.search(r"--target_class=([^ \n]+)", txt)
print((cp.group(1) if cp else "") + " " + (tc.group(1) if tc else ""))
PY
)
if [[ -z "$cp_arg" || -z "$target_class" ]]; then
  echo "Failed to parse --cp/--target_class from: $LAUNCHER" >&2
  exit 2
fi

# Expand $this_dir and normalize '::' -> ':'.
CP="${cp_arg//\$this_dir/$this_dir}"
CP="${CP//::/:}"

WORK_DIR="$ROOT_DIR/work/spf_once_${safe_name}"
HARNESS_OUT="$WORK_DIR/harness_classes"
TPL="$WORK_DIR/spf_run_${safe_name}.jpf.tpl"
mkdir -p "$HARNESS_OUT"

LISTENER_LINE="# listener=gov.nasa.jpf.symbc.SymbolicListener"
if [[ "${SPF_USE_SYMBOLIC_LISTENER:-0}" == "1" ]]; then
  LISTENER_LINE="listener=gov.nasa.jpf.symbc.SymbolicListener"
fi

SYMBOLIC_ARRAYS="${SPF_SYMBOLIC_ARRAYS:-true}"

if [[ -z "${SPF_JAVA:-}" ]]; then
  if [[ -x "$this_dir/open-jdk-8/bin/java" ]]; then
    export SPF_JAVA="$this_dir/open-jdk-8/bin/java"
  elif [[ -x "$this_dir/open-jdk-8/jre/bin/java" ]]; then
    export SPF_JAVA="$this_dir/open-jdk-8/jre/bin/java"
  fi
fi

JAVAC_BIN="javac"
if [[ -x "$this_dir/open-jdk-8/bin/javac" ]]; then
  JAVAC_BIN="$this_dir/open-jdk-8/bin/javac"
elif [[ -x "$this_dir/open-jdk-8/jre/bin/javac" ]]; then
  JAVAC_BIN="$this_dir/open-jdk-8/jre/bin/javac"
fi

SEED_LIMIT="${SPF_SEED_MAX_BYTES:-4096}"
JAVA_SEED_BYTES="$(
  python3 - <<'PY' "$SEED" "$SEED_LIMIT"
import sys
path = sys.argv[1]
limit = int(sys.argv[2])
data = open(path, "rb").read()
if len(data) > limit:
    data = data[:limit]
out = []
for i, b in enumerate(data):
    if i % 16 == 0:
        out.append("    ")
    out.append(f"(byte)0x{b:02x},")
    if i % 16 == 15:
        out.append("\n")
if data and len(data) % 16 != 0:
    out.append("\n")
sys.stdout.write("".join(out))
PY
)"

cat > "$WORK_DIR/SpfHarness.java" <<JAVA
public class SpfHarness {
  static {
    System.setProperty("file.encoding", "UTF-8");
    System.setProperty("sun.jnu.encoding", "UTF-8");
  }

  private static final byte[] SEED = new byte[] {
$JAVA_SEED_BYTES  };

  public static void run(byte[] data) {
    ${target_class}.fuzzerTestOneInput(data);
  }

  public static void main(String[] args) throws Exception {
    byte[] data = SEED.clone();
    run(data);
  }
}
JAVA

cat > "$TPL" <<EOF
target=@TARGET@
classpath=@CLASSPATH@

target.args=@SEED@

# JPF's modeled JRE can miss encoding-related sysprops; defaultCharset() then throws
# "IllegalArgumentException: Null charset name" in common libraries (e.g. commons-io).
vm.sysprop.file.encoding=UTF-8
vm.sysprop.sun.jnu.encoding=UTF-8

$LISTENER_LINE
symbolic.method=SpfHarness.run(sym)
symbolic.arrays=$SYMBOLIC_ARRAYS

vm.storage.class=nil
search.multiple_errors=true

search.depth_limit=50
symbolic.max_int=1024
symbolic.min_int=-1024

symbolic.dp=choco
symbolic.debug=true
symbolic.print=true
EOF

echo "[spf-once] compiling harness with CP from launcher: $LAUNCHER"
echo "[spf-once] using javac: $JAVAC_BIN"
if "$JAVAC_BIN" -help 2>&1 | grep -q -- '--release'; then
  "$JAVAC_BIN" -g --release 8 -cp "$CP" -d "$HARNESS_OUT" "$WORK_DIR/SpfHarness.java"
else
  "$JAVAC_BIN" -g -source 8 -target 8 -cp "$CP" -d "$HARNESS_OUT" "$WORK_DIR/SpfHarness.java"
fi

source "$ROOT_DIR/scripts/spf_env.sh"

export SPF_TARGET="SpfHarness"
export SPF_CLASSPATH="$HARNESS_OUT:$CP"
export SPF_TEMPLATE="$TPL"
echo "[spf-once] using SPF_JAVA: ${SPF_JAVA:-java}"

mkdir -p "$OUT_DIR"
echo "[spf-once] running SPF engine -> $OUT_DIR"
python3 "$ROOT_DIR/engines/spf_engine.py" "$SEED" "$OUT_DIR"
echo "[spf-once] done"
