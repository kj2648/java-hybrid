#!/usr/bin/env python3
import argparse
import base64
import hashlib
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from jazzer_launcher import build_launcher_env, parse_jazzer_launcher


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _safe_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s or "default")


@dataclass(frozen=True)
class GdartInstall:
    root: Path
    java: Path
    javac: Path
    executor: Path
    dse_jar: Path
    verifier_stub_jar: Path

    @staticmethod
    def autodetect() -> "GdartInstall":
        candidates = []
        env = os.environ.get("GDART_HOME", "").strip()
        if env:
            candidates.append(Path(os.path.expanduser(env)).resolve())
        candidates.append((Path(__file__).resolve().parents[1] / "third_party" / "gdart").resolve())
        for root in candidates:
            if root.is_dir():
                return GdartInstall.from_root(root)
        raise SystemExit(
            "[gdart] GDART not found.\n"
            "Run scripts/setup_gdart.sh (recommended), or set GDART_HOME=/path/to/gdart.\n"
            "Upstream: https://github.com/tudo-aqua/gdart"
        )

    @staticmethod
    def from_root(root: Path) -> "GdartInstall":
        root = root.resolve()
        config = root / "config"
        if not config.is_file():
            raise SystemExit(f"[gdart] missing {config} (run gdart's ./build.sh first)")

        graalvm_bin = None
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("GRAALVM_HOME="):
                graalvm_bin = line.split("=", 1)[1].strip()
                break
        if not graalvm_bin:
            raise SystemExit(f"[gdart] failed to parse GRAALVM_HOME from {config}")

        java = (root / graalvm_bin / "java").resolve()
        javac = (root / graalvm_bin / "javac").resolve()
        executor = (root / "executor.sh").resolve()

        dse_jar = root / "dse" / "target" / "dse-0.0.1-SNAPSHOT-jar-with-dependencies.jar"
        verifier_stub = root / "verifier-stub" / "target" / "verifier-stub-1.0.jar"

        missing = [p for p in (java, javac, executor, dse_jar, verifier_stub) if not p.exists()]
        if missing:
            msg = "\n".join(str(p) for p in missing)
            raise SystemExit(
                "[gdart] missing GDART build artifacts (run gdart's ./build.sh first):\n" + msg
            )

        return GdartInstall(
            root=root,
            java=java,
            javac=javac,
            executor=executor,
            dse_jar=dse_jar,
            verifier_stub_jar=verifier_stub,
        )


class Templates:
    def __init__(self, repo_root: Path):
        self.base = repo_root / "templates" / "gdart"

    def read(self, name: str) -> str:
        p = self.base / name
        if not p.is_file():
            raise SystemExit(f"[gdart] missing template: {p}")
        return p.read_text(encoding="utf-8", errors="replace")

    def render(self, name: str, mapping: dict[str, str]) -> str:
        txt = self.read(name)
        for k, v in mapping.items():
            txt = txt.replace(f"@{k}@", v)
        return txt


def _signed_byte(b: int) -> int:
    return b - 256 if b >= 128 else b


def _encode_concolic_bytes(values: bytes, *, b64encode: bool = True) -> str:
    parts: list[str] = []
    for b in values:
        s = str(_signed_byte(b)).encode("ascii")
        if b64encode:
            parts.append(base64.b64encode(s).decode("ascii"))
        else:
            parts.append(s.decode("ascii"))
    if b64encode:
        return "[b64]" + ",".join(parts)
    return ",".join(parts)


def _decode_concolic_bytes(raw: str) -> bytes:
    s = raw.strip().strip('"').strip("'").strip()
    if not s:
        return b""
    b64 = False
    if s.startswith("[b64]") or s.startswith("[64]"):
        b64 = True
        s = s.split("]", 1)[1]
    out = bytearray()
    for tok in [t for t in s.split(",") if t != ""]:
        if b64:
            tok = base64.b64decode(tok).decode("ascii", errors="replace")
        try:
            v = int(tok.strip())
        except ValueError:
            continue
        if v < 0:
            v = 256 + (v % 256)
        out.append(v & 0xFF)
    return bytes(out)


_RE_CONCOLIC_BYTES = re.compile(r"-Dconcolic\.bytes=([^\s]+)")


def main() -> int:
    ap = argparse.ArgumentParser("gdart_engine: SPouT recording + GDART solving (file-in/file-out)")
    ap.add_argument("--fuzzer-path", required=True, help="Path to an OSS-Fuzz Jazzer launcher script")
    ap.add_argument("--work-dir", required=True, help="Work directory root (for cache)")
    ap.add_argument("--seed-max-bytes", type=int, default=int(os.environ.get("GDART_SEED_MAX_BYTES", "128")))
    ap.add_argument("--solver", default=os.environ.get("GDART_SOLVER", "z3"), help="GDART solver backend id (default: z3)")
    ap.add_argument("--explore", default=os.environ.get("GDART_EXPLORE", "dfs"), help="DSE explore strategy (default: dfs)")
    ap.add_argument("--terminate-on", default=os.environ.get("GDART_TERMINATE_ON", "completion"), help="DSE terminate condition")
    ap.add_argument("seed", type=Path)
    ap.add_argument("out_dir", type=Path)
    args = ap.parse_args()

    seed_path = args.seed.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    install = GdartInstall.autodetect()
    repo_root = Path(__file__).resolve().parents[1]
    templates = Templates(repo_root)

    launcher = parse_jazzer_launcher(Path(args.fuzzer_path).expanduser().resolve())
    env = build_launcher_env(launcher)

    seed_bytes = seed_path.read_bytes() if seed_path.is_file() else b""
    max_n = max(1, int(args.seed_max_bytes))
    n = min(max_n, max(1, len(seed_bytes)))
    seed_bytes = (seed_bytes[:n] if seed_bytes else b"\x00")[:n]

    safe = _safe_id(Path(args.fuzzer_path).name)
    cache_dir = (Path(args.work_dir).expanduser().resolve() / "gdart_cache" / safe).resolve()
    src_dir = cache_dir / "src"
    classes_dir = cache_dir / "classes"
    src_dir.mkdir(parents=True, exist_ok=True)
    classes_dir.mkdir(parents=True, exist_ok=True)

    wrapper_exec = cache_dir / "executor_wrapper.sh"
    desired_wrapper = "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            f"REAL_EXEC={shlex.quote(str(install.executor))}",
            "",
            "bytes_args=()",
            "out=()",
            'for arg in "$@"; do',
            '  if [[ "$arg" == -Dconcolic.bytes=* ]]; then',
            '    bytes_args+=("$arg")',
            "    continue",
            "  fi",
            '  out+=("$arg")',
            "done",
            "",
            "if [[ ${#bytes_args[@]} -eq 0 ]]; then",
            '  exec "$REAL_EXEC" "${out[@]}"',
            "fi",
            "",
            "pick_prefix() {",
            '  local v="$1"',
            '  if [[ "$v" == \\[*\\]* ]]; then',
            "    echo \"${v%%]*}]\"",
            "  else",
            "    echo \"\"",
            "  fi",
            "}",
            "",
            "strip_prefix() {",
            '  local v="$1"',
            '  if [[ "$v" == \\[*\\]* ]]; then',
            "    echo \"${v#*]}\"",
            "  else",
            "    echo \"$v\"",
            "  fi",
            "}",
            "",
            "base_idx=$(( ${#bytes_args[@]} - 1 ))",
            "base_val=\"${bytes_args[$base_idx]#*=}\"",
            "base_prefix=\"$(pick_prefix \"$base_val\")\"",
            "base_list=\"$(strip_prefix \"$base_val\")\"",
            "IFS=',' read -r -a base_toks <<< \"$base_list\"",
            "",
            "final_val=\"${bytes_args[0]#*=}\"",
            "final_prefix=\"$(pick_prefix \"$final_val\")\"",
            "final_list=\"$(strip_prefix \"$final_val\")\"",
            "IFS=',' read -r -a final_toks <<< \"$final_list\"",
            "",
            "if [[ ${#bytes_args[@]} -ge 2 ]]; then",
            "  k=${#final_toks[@]}",
            "  if [[ $k -lt ${#base_toks[@]} ]]; then",
            "    merged=(\"${final_toks[@]}\" \"${base_toks[@]:$k}\")",
            "  else",
            "    merged=(\"${final_toks[@]}\")",
            "  fi",
            "  if [[ -n \"$final_prefix\" ]]; then",
            "    final_prefix=\"$final_prefix\"",
            "  else",
            "    final_prefix=\"$base_prefix\"",
            "  fi",
            "  final_list=\"${merged[0]}\"",
            "  for ((i=1; i<${#merged[@]}; i++)); do",
            "    final_list+=\",${merged[$i]}\"",
            "  done",
            "fi",
            "",
            "out=(\"-Dconcolic.bytes=${final_prefix}${final_list}\" \"${out[@]}\")",
            'exec "$REAL_EXEC" "${out[@]}"',
            "",
        ]
    )
    try:
        current = wrapper_exec.read_text(encoding="utf-8", errors="replace")
    except Exception:
        current = ""
    if current != desired_wrapper:
        wrapper_exec.write_text(desired_wrapper, encoding="utf-8")
        try:
            wrapper_exec.chmod(0o755)
        except Exception:
            pass

    harness_java = src_dir / "GdartHarness.java"
    fp_file = cache_dir / "fingerprint.sha256"

    harness_src = templates.render(
        "GdartHarness.java.tpl",
        {
            "TARGET_CLASS": launcher.target_class,
            "SEED_LIMIT": str(max_n),
        },
    )
    fp_payload = "\n".join(
        [
            f"gdart_root={install.root}",
            f"java={install.java}",
            f"javac={install.javac}",
            f"dse_jar={install.dse_jar}",
            f"verifier_stub={install.verifier_stub_jar}",
            f"classpath={launcher.classpath}",
            f"target_class={launcher.target_class}",
            f"seed_limit={max_n}",
            f"harness={hashlib.sha256(harness_src.encode()).hexdigest()}",
        ]
    ).encode()
    fp = hashlib.sha256(fp_payload).hexdigest()
    have = (classes_dir / "GdartHarness.class").is_file()
    if (not fp_file.is_file()) or (not have) or (fp_file.read_text(encoding="utf-8", errors="replace").strip() != fp):
        _write_text(harness_java, harness_src)
        cp_compile = f"{install.verifier_stub_jar}:{launcher.classpath}"
        subprocess.check_call([str(install.javac), "-g", "-cp", cp_compile, "-d", str(classes_dir), str(harness_java)])
        _write_text(fp_file, fp + "\n")

    cp_runtime = f"{classes_dir}:{install.verifier_stub_jar}:{launcher.classpath}"
    seed_prop = _encode_concolic_bytes(seed_bytes, b64encode=True)
    exec_args = " ".join(
        [
            f"-Dconcolic.bytes={seed_prop}",
            f"-cp {cp_runtime}",
            "-Dconcolic.execution=true",
            "-Dtaint.flow=OFF",
            f"-Djfo.input_len={n}",
            "GdartHarness",
        ]
    )

    cmd = [
        str(install.java),
        "-cp",
        str(install.dse_jar),
        "tools.aqua.dse.DSELauncher",
        f"-Ddse.executor={wrapper_exec}",
        f"-Ddse.executor.args={exec_args}",
        f"-Ddse.sources={cp_runtime}",
        "-Ddse.b64encode=true",
        "-Ddse.witness=false",
        f"-Ddse.dp={args.solver}",
        f"-Ddse.explore={args.explore}",
        f"-Ddse.terminate.on={args.terminate_on}",
    ]

    print("[gdart] install_root=", install.root)
    print("[gdart] seed=", seed_path)
    print("[gdart] out_dir=", out_dir)
    print("[gdart] nbytes=", n, "seed_max_bytes=", max_n)
    print("[gdart] target_class=", launcher.target_class)
    print("[gdart] cmd=", shlex.join(cmd))

    seen: set[str] = set()
    log_dir = out_dir / "gdart_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    out_log = log_dir / "gdart_engine.log"
    with out_log.open("wb") as lf:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True)
        assert p.stdout is not None
        for line in p.stdout:
            sys.stdout.write(line)
            try:
                lf.write(line.encode("utf-8", errors="replace"))
            except Exception:
                pass
            m = _RE_CONCOLIC_BYTES.search(line)
            if not m:
                continue
            model = _decode_concolic_bytes(m.group(1))
            if not model:
                continue
            if len(model) < n:
                model = model + seed_bytes[len(model) : n]
            if len(model) > n:
                model = model[:n]
            h = hashlib.sha256(model).hexdigest()[:16]
            if h in seen:
                continue
            seen.add(h)
            out_path = out_dir / f"gdart_{h}_{len(model)}"
            try:
                out_path.write_bytes(model)
            except Exception:
                pass

        p.wait()
        rc = int(p.returncode or 0)

    if rc != 0:
        if seen:
            print(f"[gdart] warning: DSELauncher exited rc={rc}, but generated={len(seen)} seeds; continuing")
            return 0
        raise SystemExit(f"[gdart] DSELauncher failed rc={rc} (see {out_log})")

    print(f"[gdart] generated={len(seen)} seeds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
