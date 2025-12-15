#!/usr/bin/env python3
import os
import shutil
import subprocess
import time
import hashlib
import sys
from pathlib import Path


class SPFEngine:
    class Config:
        def __init__(self,
                     target: str,
                     classpath: str,
                     jpf_core: str,
                     jpf_symbc: str,
                     java: str = "java",
                     jvm_opts: str = "-Xmx2g",
                     template: str = "templates/spf_run.jpf.tpl",
                     time_budget: int = 30,
                     max_outputs: int = 50,
                     max_len: int = 4096):
            self.target = target
            self.classpath = classpath
            self.jpf_core = jpf_core
            self.jpf_symbc = jpf_symbc
            self.java = java
            self.jvm_opts = jvm_opts
            self.template = template
            self.time_budget = time_budget
            self.max_outputs = max_outputs
            self.max_len = max_len

    def __init__(self, cfg: 'SPFEngine.Config'):
        self.cfg = cfg

    # --- helpers ---
    @staticmethod
    def _mkdir(p: Path):
        p.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sha1(data: bytes) -> str:
        return hashlib.sha1(data).hexdigest()

    def _write_jpf(self, out: Path, seed_path: Path):
        txt = Path(self.cfg.template).read_text()
        txt = txt.replace("@TARGET@", self.cfg.target)
        txt = txt.replace("@CLASSPATH@", self.cfg.classpath)
        txt = txt.replace("@SEED@", str(seed_path))
        out.write_text(txt)

    # --- core ---
    def run(self, seed: Path, out_dir: Path):
        """
        Contract: produce zero or more files under out_dir
        """
        work = out_dir / f"spf_{int(time.time()*1000)}"
        self._mkdir(out_dir)
        self._mkdir(work)

        seed_copy = work / "seed"
        shutil.copyfile(seed, seed_copy)

        jpf_file = work / "run.jpf"
        self._write_jpf(jpf_file, seed_copy)

        env = os.environ.copy()
        env["JPF_HOME"] = self.cfg.jpf_core
        env["JPF_SYMBC"] = self.cfg.jpf_symbc

        runjpf_jar = Path(self.cfg.jpf_core) / "build" / "RunJPF.jar"
        if not runjpf_jar.is_file():
            raise FileNotFoundError(
                f"Missing RunJPF.jar: {runjpf_jar}\n"
                f"Run scripts/setup_spf.sh (or build jpf-core) to generate it."
            )

        cmd = [
            self.cfg.java,
            *self.cfg.jvm_opts.split(),
            "-jar",
            str(runjpf_jar),
            f"+site={os.environ['SPF_SITE']}" if 'SPF_SITE' in os.environ else None,
            str(jpf_file),
        ]
        cmd = [c for c in cmd if c is not None]

        log = work / "spf.log"
        with log.open("wb") as fp:
            p = subprocess.Popen(cmd, cwd=work, stdout=fp, stderr=subprocess.STDOUT, env=env)
            try:
                p.wait(timeout=self.cfg.time_budget)
            except subprocess.TimeoutExpired:
                p.kill()

        # collect with cap + in-memory dedup
        kept = 0
        seen_hashes = set()
        for f in work.rglob("*"):
            if not f.is_file():
                continue
            if f in {seed_copy, jpf_file, log}:
                continue
            if f.stat().st_size == 0:
                continue
            # dump to out_dir with cap + dedup
            data = f.read_bytes()
            if len(data) == 0 or len(data) > self.cfg.max_len:
                continue
            h = self._sha1(data)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            out = out_dir / f"id_{kept:06d}.dse"
            if not out.exists():
                out.write_bytes(data)
                kept += 1
                if kept >= self.cfg.max_outputs:
                    break


def main():
    if len(sys.argv) < 3:
        print("usage: spf_engine.py <seed> <out_dir>", file=sys.stderr)
        sys.exit(2)

    seed = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()

    try:
        target = os.environ["SPF_TARGET"]
        classpath = os.environ["SPF_CLASSPATH"]
        jpf_core = os.environ.get("SPF_JPF_CORE", os.environ["JPF_HOME"])
        jpf_symbc = os.environ.get("SPF_JPF_SYMBC", os.environ["JPF_SYMBC"])
    except KeyError as e:
        print(f"[spf_engine] missing env: {e}", file=sys.stderr)
        sys.exit(2)

    cfg = SPFEngine.Config(
        target=target,
        classpath=classpath,
        jpf_core=jpf_core,
        jpf_symbc=jpf_symbc,
        java=os.environ.get("SPF_JAVA", "java"),
        jvm_opts=os.environ.get("SPF_JVM_OPTS", "-Xmx2g"),
        template=os.environ.get("SPF_TEMPLATE", "templates/spf_run.jpf.tpl"),
        time_budget=int(os.environ.get("SPF_TIME_BUDGET", "30")),
        max_outputs=int(os.environ.get("SPF_MAX_OUTPUTS", "50")),
        max_len=int(os.environ.get("SPF_MAX_LEN", "4096")),
    )

    engine = SPFEngine(cfg)

    engine.run(seed, out_dir)


if __name__ == "__main__":
    main()
