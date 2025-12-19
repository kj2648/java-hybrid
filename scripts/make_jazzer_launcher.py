#!/usr/bin/env python3
import argparse
import os
import os.path
from pathlib import Path


def _require_no_whitespace(flag: str, value: str) -> None:
    if any(ch.isspace() for ch in value):
        raise SystemExit(f"{flag} must not contain whitespace: {value!r}")

def _is_relative_to(path: Path, other: Path) -> bool:
    try:
        path.relative_to(other)
        return True
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(
        "make_jazzer_launcher: generate a Jazzer-style launcher script (parsable by engines/jazzer_launcher.py)"
    )
    ap.add_argument("--out", required=True, help="Output path for the launcher script")
    ap.add_argument("--cp", required=True, help="Classpath for Jazzer (--cp=...)")
    ap.add_argument("--target-class", required=True, help="Fuzz target class for Jazzer (--target_class=...)")
    ap.add_argument(
        "--jazzer-bin",
        default="",
        help="Path to jazzer executable used by the launcher (can reference $this_dir); defaults to third_party/atl-jazzer/bazel-bin/jazzer",
    )
    ap.add_argument(
        "--jvm-args",
        default="",
        help='Optional JVM args passed via --jvm_args="..." (no newlines)',
    )
    ap.add_argument(
        "--java-home",
        default="",
        help="Optional JAVA_HOME to export (can reference $this_dir)",
    )
    ap.add_argument(
        "--ld-library-path",
        default="",
        help="Optional LD_LIBRARY_PATH to export (can reference $JAVA_HOME, $LD_LIBRARY_PATH, $this_dir)",
    )
    args = ap.parse_args()

    _require_no_whitespace("--cp", args.cp)
    _require_no_whitespace("--target-class", args.target_class)
    if "\n" in args.jvm_args or "\r" in args.jvm_args:
        raise SystemExit("--jvm-args must not contain newlines")

    out = Path(os.path.expanduser(args.out)).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    jazzer_bin = args.jazzer_bin
    if not jazzer_bin:
        repo_root = Path(__file__).resolve().parents[1]
        default_jazzer = (repo_root / "third_party" / "atl-jazzer" / "bazel-bin" / "jazzer").resolve()
        if _is_relative_to(out, repo_root):
            rel = os.path.relpath(str(default_jazzer), str(out.parent))
            jazzer_bin = f"$this_dir/{rel}"
        else:
            jazzer_bin = str(default_jazzer)

    lines: list[str] = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        'this_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
    ]
    if args.java_home:
        lines += [f'export JAVA_HOME="{args.java_home}"', 'export PATH="$JAVA_HOME/bin:$PATH"']
    if args.ld_library_path:
        lines += [f'export LD_LIBRARY_PATH="{args.ld_library_path}"']

    exec_parts = [f'"{jazzer_bin}"', f"--cp={args.cp}", f"--target_class={args.target_class}"]
    if args.jvm_args:
        exec_parts.append(f'--jvm_args="{args.jvm_args}"')
    exec_parts.append('"$@"')

    lines += ["", "exec " + " ".join(exec_parts), ""]
    out.write_text("\n".join(lines), encoding="utf-8")
    out.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
