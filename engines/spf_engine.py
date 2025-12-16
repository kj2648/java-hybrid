#!/usr/bin/env python3
import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from jazzer_launcher import (
    build_launcher_env,
    javac_args_for_java8,
    parse_jazzer_launcher,
    pick_java_binaries,
    pick_jvm_opts,
)


def _write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@dataclass(frozen=True)
class SpfRunTuning:
    seed_limit: int
    symbolic_arrays: str
    use_symbolic_listener: bool

    @staticmethod
    def from_env() -> "SpfRunTuning":
        return SpfRunTuning(
            seed_limit=int(os.environ.get("SPF_SEED_MAX_BYTES", "4096")),
            symbolic_arrays=os.environ.get("SPF_SYMBOLIC_ARRAYS", "true"),
            use_symbolic_listener=os.environ.get("SPF_USE_SYMBOLIC_LISTENER", "0") == "1",
        )


@dataclass(frozen=True)
class JpfInstall:
    jpf_home: Path
    jpf_symbc: Path
    site_properties: Path

    @staticmethod
    def from_env(repo_root: Path) -> "JpfInstall":
        jpf_home = Path(os.environ.get("JPF_HOME", str((repo_root / "third_party" / "spf" / "jpf-core").resolve()))).resolve()
        jpf_symbc = Path(os.environ.get("JPF_SYMBC", str((repo_root / "third_party" / "spf" / "jpf-symbc").resolve()))).resolve()
        site = Path(os.environ.get("SPF_SITE", str((repo_root / "third_party" / "spf" / "site.properties").resolve()))).resolve()
        return JpfInstall(jpf_home=jpf_home, jpf_symbc=jpf_symbc, site_properties=site)

    def runjpf_jar(self) -> Path:
        p = self.jpf_home / "build" / "RunJPF.jar"
        if not p.is_file():
            raise SystemExit(
                f"[spf] missing RunJPF.jar: {p}\n"
                "Run scripts/setup_spf.sh (or build jpf-core) first."
            )
        return p

    def host_classpath(self) -> str:
        return ":".join(
            [
                str(self.jpf_home / "build" / "jpf.jar"),
                str(self.jpf_home / "build" / "jpf-classes.jar"),
                str(self.jpf_home / "build" / "jpf-annotations.jar"),
                str(self.jpf_symbc / "build" / "jpf-symbc.jar"),
                str(self.jpf_symbc / "build" / "jpf-symbc-classes.jar"),
                str(self.jpf_symbc / "build" / "jpf-symbc-annotations.jar"),
            ]
        )

    def pick_dp(self) -> str:
        dp = os.environ.get("SPF_DP", "").strip()
        if dp:
            return dp
        z3_jar = self.jpf_symbc / "lib" / "com.microsoft.z3.jar"
        z3_native = [
            self.jpf_symbc / "lib" / "libz3java.so",
            self.jpf_symbc / "lib" / "libz3java.dylib",
            self.jpf_symbc / "lib" / "libz3java.dll",
            self.jpf_symbc / "lib" / "64bit" / "libz3java.so",
            self.jpf_symbc / "lib" / "64bit" / "libz3java.dylib",
            self.jpf_symbc / "lib" / "64bit" / "libz3java.dll",
        ]
        if z3_jar.is_file() and any(p.is_file() for p in z3_native):
            return "z3bitvector"
        return "choco"

    def augment_env(self, env: dict[str, str]) -> None:
        """
        SPF/JPF-specific environment adjustments (native libs).
        """
        libp = f"{self.jpf_symbc}/lib:{self.jpf_symbc}/lib/64bit"
        ld = env.get("LD_LIBRARY_PATH", "")
        if libp not in ld:
            env["LD_LIBRARY_PATH"] = f"{libp}:{ld}" if ld else libp


class SpfTemplates:
    def __init__(self, repo_root: Path):
        self.base = repo_root / "templates" / "spf"

    def read(self, name: str) -> str:
        p = self.base / name
        if not p.is_file():
            raise SystemExit(f"[spf] missing template: {p}")
        return p.read_text(encoding="utf-8", errors="replace")

    def render(self, name: str, mapping: dict[str, str]) -> str:
        txt = self.read(name)
        for k, v in mapping.items():
            txt = txt.replace(f"@{k}@", v)
        return txt


@dataclass(frozen=True)
class PreparedHarness:
    cache_dir: Path
    classes_dir: Path
    target: str
    classpath: str
    java: str
    dp: str
    seed_limit: int
    symbolic_arrays: str
    use_symbolic_listener: bool
    runjpf_jar: Path
    site_properties: Path
    jpf: JpfInstall


class SpfEngine:
    """
    SPF runner for Jazzer-style OSS-Fuzz launchers.

    Flow:
      1) Parse launcher -> classpath + target fuzzer class
      2) Prepare (generate + compile) SpfHarness + SpfSeedDumperListener into cache
      3) For each seed: encode -> render run.jpf -> run RunJPF.jar -> collect spf_solutions/*.bin
    """

    def __init__(self, *, fuzzer_path: Path, work_dir: Path):
        self.repo_root = Path(__file__).resolve().parents[1]
        self.fuzzer_path = fuzzer_path.resolve()
        self.work_dir = work_dir.resolve()
        self.tuning = SpfRunTuning.from_env()
        self.templates = SpfTemplates(self.repo_root)
        self.jpf = JpfInstall.from_env(self.repo_root)

        try:
            self.launcher = parse_jazzer_launcher(self.fuzzer_path)
        except ValueError as e:
            raise SystemExit(f"[spf] {e}") from e

        self.target_class = self.launcher.target_class
        self.launcher_cp = self.launcher.classpath
        self.dp = self.jpf.pick_dp()

    def prepare(self) -> PreparedHarness:
        java, javac = pick_java_binaries(self.launcher)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.fuzzer_path.name)
        cache_dir = (self.work_dir / "spf_cache" / safe).resolve()
        src_dir = cache_dir / "src"
        classes_dir = cache_dir / "classes"
        src_dir.mkdir(parents=True, exist_ok=True)
        classes_dir.mkdir(parents=True, exist_ok=True)

        harness_java = src_dir / "SpfHarness.java"
        listener_java = src_dir / "SpfSeedDumperListener.java"
        fp_file = cache_dir / "fingerprint.sha256"

        harness_src = self.templates.render(
            "SpfHarness.java.tpl",
            {"TARGET_CLASS": self.target_class, "SEED_LIMIT": str(self.tuning.seed_limit)},
        )
        listener_src = self.templates.read("SpfSeedDumperListener.java")
        jpf_tpl = self.templates.read("spf_run.jpf.tpl")

        host_cp = self.jpf.host_classpath()
        fp_payload = "\n".join(
            [
                f"fuzzer={self.fuzzer_path}",
                f"java={java}",
                f"javac={javac}",
                f"launcher_cp={self.launcher_cp}",
                f"target_class={self.target_class}",
                f"seed_limit={self.tuning.seed_limit}",
                f"dp={self.dp}",
                f"jpf_home={self.jpf.jpf_home}",
                f"jpf_symbc={self.jpf.jpf_symbc}",
                f"host_cp={host_cp}",
                f"listener={hashlib.sha256(listener_src.encode()).hexdigest()}",
                f"harness={hashlib.sha256(harness_src.encode()).hexdigest()}",
                f"jpf_tpl={hashlib.sha256(jpf_tpl.encode()).hexdigest()}",
            ]
        ).encode()
        fp = hashlib.sha256(fp_payload).hexdigest()
        have_classes = (classes_dir / "SpfHarness.class").is_file() and (classes_dir / "SpfSeedDumperListener.class").is_file()
        if fp_file.is_file() and have_classes and fp_file.read_text(encoding="utf-8", errors="replace").strip() == fp:
            return self._prepared(cache_dir, classes_dir, java=java)

        _write_text(harness_java, harness_src)
        _write_text(listener_java, listener_src)

        javac_args = javac_args_for_java8(javac)

        subprocess.check_call(javac_args + ["-cp", self.launcher_cp, "-d", str(classes_dir), str(harness_java)])
        subprocess.check_call(javac_args + ["-cp", host_cp, "-d", str(classes_dir), str(listener_java)])
        _write_text(fp_file, fp + "\n")

        return self._prepared(cache_dir, classes_dir, java=java)

    def _prepared(self, cache_dir: Path, classes_dir: Path, *, java: str) -> PreparedHarness:
        target = "SpfHarness"
        classpath = f"{classes_dir}:{self.launcher_cp}"
        return PreparedHarness(
            cache_dir=cache_dir,
            classes_dir=classes_dir,
            target=target,
            classpath=classpath,
            java=java,
            dp=self.dp,
            seed_limit=self.tuning.seed_limit,
            symbolic_arrays=self.tuning.symbolic_arrays,
            use_symbolic_listener=self.tuning.use_symbolic_listener,
            runjpf_jar=self.jpf.runjpf_jar(),
            site_properties=self.jpf.site_properties,
            jpf=self.jpf,
        )

    def run_seed(self, *, seed: Path, out_dir: Path):
        prepared = self.prepare()
        seed_b64, seed_tag = self._encode_seed(seed, prepared.seed_limit)
        with tempfile.TemporaryDirectory(prefix="spf_run_", dir=None) as tmp:
            run_dir = Path(tmp)
            jpf_file = self._write_run_jpf(run_dir, prepared, seed_b64, out_dir)
            cmd, env = self._build_run_command(prepared, jpf_file)
            log_path = self._log_path(out_dir, seed_tag)
            self._run_jpf(cmd=cmd, env=env, cwd=run_dir, log_path=log_path)

    @staticmethod
    def _encode_seed(seed: Path, seed_limit: int) -> tuple[str, str]:
        seed_bytes = seed.read_bytes()
        if len(seed_bytes) > seed_limit:
            seed_bytes = seed_bytes[:seed_limit]
        seed_b64 = base64.b64encode(seed_bytes).decode("ascii")
        seed_tag = hashlib.sha256(seed_bytes).hexdigest()[:12]
        return seed_b64, seed_tag

    def _write_run_jpf(self, run_dir: Path, prepared: PreparedHarness, seed_b64: str, out_dir: Path) -> Path:
        jpf_file = run_dir / "run.jpf"
        listener_line = "# listener=gov.nasa.jpf.symbc.SymbolicListener"
        if prepared.use_symbolic_listener:
            listener_line = "listener=gov.nasa.jpf.symbc.SymbolicListener"
        _write_text(
            jpf_file,
            self.templates.render(
                "spf_run.jpf.tpl",
                {
                    "TARGET": prepared.target,
                    "CLASSPATH": prepared.classpath,
                    "SEED_B64": seed_b64,
                    "HARNESS_OUT": str(prepared.classes_dir),
                    "OUT_DIR": str(out_dir),
                    "DP": prepared.dp,
                    "SEED_LIMIT": str(prepared.seed_limit),
                    "SYMBOLIC_ARRAYS": prepared.symbolic_arrays,
                    "LISTENER_LINE": listener_line,
                },
            ),
        )
        return jpf_file

    def _build_run_command(self, prepared: PreparedHarness, jpf_file: Path) -> tuple[list[str], dict[str, str]]:
        env = self._build_process_env(prepared)
        jvm_opts = self._pick_jvm_opts(env)
        cmd = [
            prepared.java,
            *jvm_opts,
            "-jar",
            str(prepared.runjpf_jar),
            f"+site={prepared.site_properties}" if prepared.site_properties else None,
            str(jpf_file),
        ]
        cmd = [c for c in cmd if c is not None]
        return cmd, env

    def _build_process_env(self, prepared: PreparedHarness) -> dict[str, str]:
        env = build_launcher_env(self.launcher)
        env["JPF_HOME"] = str(prepared.jpf.jpf_home)
        env["JPF_SYMBC"] = str(prepared.jpf.jpf_symbc)
        self.jpf.augment_env(env)
        return env

    def _pick_jvm_opts(self, env: dict[str, str]) -> list[str]:
        opts = pick_jvm_opts(env, self.launcher, env_key="SPF_JVM_OPTS", default="-Xmx2g")

        # Z3 Java bindings require native lib discoverable via java.library.path.
        if self.dp.startswith("z3") and not any(o.startswith("-Djava.library.path=") for o in opts):
            libp = f"{self.jpf.jpf_symbc}/lib:{self.jpf.jpf_symbc}/lib/64bit"
            opts.append(f"-Djava.library.path={libp}")
        return opts

    @staticmethod
    def _log_path(out_dir: Path, seed_tag: str) -> Path:
        log_dir = out_dir / "spf_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        return log_dir / f"spf_{int(time.time()*1000)}_{seed_tag}.log"

    @staticmethod
    def _run_jpf(*, cmd: list[str], env: dict[str, str], cwd: Path, log_path: Path):
        with log_path.open("wb") as fp:
            p = subprocess.Popen(cmd, cwd=cwd, stdout=fp, stderr=subprocess.STDOUT, env=env)
            p.wait()

def main() -> int:
    ap = argparse.ArgumentParser("spf_engine: run SPF for a Jazzer-style fuzzer target")
    ap.add_argument("--fuzzer-path", required=True, help="Path to Jazzer-style OSS-Fuzz launcher script/binary")
    ap.add_argument("--work-dir", required=True, help="Work directory root (used for SPF cache)")
    ap.add_argument("seed", nargs="?", help="Seed file path")
    ap.add_argument("out_dir", nargs="?", help="Output directory path")
    args = ap.parse_args()

    fuzzer_path = Path(os.path.expanduser(args.fuzzer_path)).resolve()
    if not fuzzer_path.is_file():
        print(f"[spf] fuzzer path not found: {fuzzer_path}", file=sys.stderr)
        return 2
    if not args.seed or not args.out_dir:
        print("usage: spf_engine.py --fuzzer-path PATH --work-dir WORK <seed> <out_dir>", file=sys.stderr)
        return 2

    work_dir = Path(os.path.expanduser(args.work_dir)).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    engine = SpfEngine(fuzzer_path=fuzzer_path, work_dir=work_dir)

    seed = Path(args.seed).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    engine.run_seed(seed=seed, out_dir=out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
