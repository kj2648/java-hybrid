#!/usr/bin/env python3
import argparse
import os
import re
from pathlib import Path


_RE_CP = re.compile(r"--cp=([^ \n]+)")
_RE_TC = re.compile(r"--target_class=([^ \n]+)")

def _abspath_no_symlink(p: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(p))))


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def _read_launcher_fields(launcher_path: Path) -> tuple[str, str]:
    txt = launcher_path.read_text(encoding="utf-8", errors="replace")
    cp_m = _RE_CP.search(txt)
    tc_m = _RE_TC.search(txt)
    cp_arg = _strip_quotes(cp_m.group(1)) if cp_m else ""
    target_class = _strip_quotes(tc_m.group(1)) if tc_m else ""
    if not cp_arg or not target_class:
        raise SystemExit(f"failed to parse --cp/--target_class from launcher: {launcher_path}")
    return cp_arg, target_class


def main() -> int:
    ap = argparse.ArgumentParser(
        "make_atl_jazzer_wrapper_from_ossfuzz: generate a launcher that uses atl-jazzer without modifying OSS-Fuzz build/out"
    )
    ap.add_argument(
        "--ossfuzz-launcher",
        required=True,
        help="Path to an existing OSS-Fuzz Jazzer launcher (e.g. .../build/out/<project>/<FuzzerName>)",
    )
    ap.add_argument("--out", required=True, help="Output path for the generated wrapper script")
    ap.add_argument(
        "--atl-driver",
        default="",
        help="Path to atl-jazzer native launcher binary; defaults to third_party/atl-jazzer/bazel-bin/launcher/jazzer",
    )
    ap.add_argument(
        "--agent-jar",
        default="",
        help=(
            "Path to atl-jazzer's jazzer_standalone_deploy.jar (used by the native launcher). "
            "Defaults to <atl_driver_dir>/jazzer.runfiles/_main/src/main/java/com/code_intelligence/jazzer/jazzer_standalone_deploy.jar"
        ),
    )
    ap.add_argument(
        "--java-home",
        default="",
        help="JAVA_HOME to use. Defaults to <ossfuzz_out>/open-jdk-8 if present, otherwise unset.",
    )
    ap.add_argument(
        "--ld-library-path",
        default="",
        help="LD_LIBRARY_PATH to use. Defaults to <ossfuzz_out> (same as OSS-Fuzz launcher).",
    )
    ap.add_argument("--zmq-router-addr", default="", help="Set ATLJAZZER_ZMQ_ROUTER_ADDR (enables OOFMutate)")
    ap.add_argument("--zmq-harness-id", default="", help="Set ATLJAZZER_ZMQ_HARNESS_ID (enables OOFMutate)")
    ap.add_argument("--zmq-shm-name", default="", help="Optional ATLJAZZER_ZMQ_SHM_NAME (must match router)")
    ap.add_argument("--zmq-dealer-id", default="", help="Optional ATLJAZZER_ZMQ_DEALER_ID")
    ap.add_argument("--zmq-dealer-log", default="", help="Optional ATLJAZZER_ZMQ_DEALER_LOG")
    args = ap.parse_args()

    oss_launcher = Path(os.path.expanduser(args.ossfuzz_launcher)).resolve()
    if not oss_launcher.is_file():
        raise SystemExit(f"--ossfuzz-launcher not found: {oss_launcher}")

    repo_root = Path(__file__).resolve().parents[1]
    oss_out_dir = oss_launcher.parent

    atl_driver = args.atl_driver
    if not atl_driver:
        atl_driver = str(repo_root / "third_party" / "atl-jazzer" / "bazel-bin" / "launcher" / "jazzer")
    atl_driver_p = _abspath_no_symlink(Path(atl_driver))
    if not atl_driver_p.exists():
        raise SystemExit(f"atl-jazzer driver not found: {atl_driver_p}\nHint: build atl-jazzer: cd third_party/atl-jazzer && bazelisk build //:jazzer")

    # atl-jazzer's native launcher needs jazzer_standalone_deploy.jar to bootstrap the Java side.
    # If we point --agent_path at the OSS-Fuzz jazzer_agent_deploy.jar, we may accidentally run the
    # *non-atl* driver (no OOFMutate Dealer), which makes ZMQ integration appear "dead".
    atl_runfiles = atl_driver_p.parent / "jazzer.runfiles"
    atl_standalone_jar_default = (
        atl_runfiles / "_main" / "src" / "main" / "java" / "com" / "code_intelligence" / "jazzer" / "jazzer_standalone_deploy.jar"
    )

    agent_jar = args.agent_jar
    if not agent_jar:
        agent_jar = str(atl_standalone_jar_default)
    agent_jar_p = _abspath_no_symlink(Path(agent_jar))
    if not agent_jar_p.is_file():
        raise SystemExit(
            "atl-jazzer standalone jar not found (needed for atl mode):\n"
            f"  expected: {atl_standalone_jar_default}\n"
            f"  got:      {agent_jar_p}\n"
            "Hint: build atl-jazzer: cd third_party/atl-jazzer && bazelisk build //:jazzer"
        )

    java_home = args.java_home
    if not java_home:
        cand = oss_out_dir / "open-jdk-8"
        if cand.is_dir():
            java_home = str(_abspath_no_symlink(cand))
    ld_library_path = args.ld_library_path or str(_abspath_no_symlink(oss_out_dir))

    cp_arg, target_class = _read_launcher_fields(oss_launcher)
    # Preserve "::" exactly as in the original launcher, but expand $this_dir to the OSS-Fuzz out dir.
    cp_arg = cp_arg.replace("$this_dir", str(oss_out_dir)).replace("${this_dir}", str(oss_out_dir))

    out = Path(os.path.expanduser(args.out)).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Auto-generated wrapper to run an OSS-Fuzz Jazzer target using atl-jazzer binaries.",
        f'# Source launcher: "{oss_launcher}"',
        f'# atl-jazzer driver: "{atl_driver_p}"',
        f'# atl-jazzer standalone jar: "{agent_jar_p}"',
        "",
        "if [[ \"$@\" =~ (^|[[:space:]])-runs=[0-9]+($|[[:space:]]) ]]; then",
        "  mem_settings='-Xmx1900m:-Xss900k'",
        "else",
        "  mem_settings='-Xmx2048m:-Xss1024k'",
        "fi",
        "",
    ]
    if java_home:
        lines += [f'export JAVA_HOME="{java_home}"', 'export PATH="$JAVA_HOME/bin:$PATH"']
    if ld_library_path:
        lines += [f'export LD_LIBRARY_PATH="{ld_library_path}"']

    if args.zmq_router_addr or args.zmq_harness_id:
        if not (args.zmq_router_addr and args.zmq_harness_id):
            raise SystemExit("--zmq-router-addr and --zmq-harness-id must be provided together")
        lines += [
            f'export ATLJAZZER_ZMQ_ROUTER_ADDR="${{ATLJAZZER_ZMQ_ROUTER_ADDR:-{args.zmq_router_addr}}}"',
            f'export ATLJAZZER_ZMQ_HARNESS_ID="${{ATLJAZZER_ZMQ_HARNESS_ID:-{args.zmq_harness_id}}}"',
        ]
        if args.zmq_shm_name:
            lines.append(f'export ATLJAZZER_ZMQ_SHM_NAME="${{ATLJAZZER_ZMQ_SHM_NAME:-{args.zmq_shm_name}}}"')
        if args.zmq_dealer_id:
            lines.append(f'export ATLJAZZER_ZMQ_DEALER_ID="${{ATLJAZZER_ZMQ_DEALER_ID:-{args.zmq_dealer_id}}}"')
        if args.zmq_dealer_log:
            lines.append(f'export ATLJAZZER_ZMQ_DEALER_LOG="${{ATLJAZZER_ZMQ_DEALER_LOG:-{args.zmq_dealer_log}}}"')

    lines += [
        "",
        f'exec "{atl_driver_p}" '
        f'--agent_path="{agent_jar_p}" '
        f'--cp={cp_arg} '
        f'--target_class={target_class} '
        '--jvm_args="$mem_settings" '
        '"$@"',
        "",
    ]

    out.write_text("\n".join(lines), encoding="utf-8")
    out.chmod(0o755)
    print(f"[ok] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
