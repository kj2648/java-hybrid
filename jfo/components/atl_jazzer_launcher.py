import subprocess
import sys
from pathlib import Path

from jfo.util.workdir import WorkDir


class AtlJazzerLauncherGenerator:
    def __init__(self, *, workdir: WorkDir):
        self.workdir = workdir
        # Repo layout:
        #   <repo>/jfo/components/atl_jazzer_launcher.py  (this file)
        #   <repo>/scripts/...                           (helper scripts)
        self.repo_root = Path(__file__).resolve().parents[2]
        self.script = (self.repo_root / "scripts" / "make_atl_jazzer_wrapper_from_ossfuzz.py").resolve()
        if not self.script.is_file():
            raise SystemExit(f"missing wrapper generator script: {self.script}")

    def wrapper_path(self, launcher: Path) -> Path:
        return (self.workdir.root / "fuzzer" / f"atl_{launcher.name}").resolve()

    def ensure(self, *, ossfuzz_launcher: Path, router_addr: str, harness_id: str) -> Path:
        out = self.wrapper_path(ossfuzz_launcher)
        out.parent.mkdir(parents=True, exist_ok=True)
        dealer_log = (self.workdir.root / "logs" / f"dealer_{harness_id}.log").resolve()

        if out.is_file():
            try:
                txt = out.read_text(encoding="utf-8", errors="replace")
            except Exception:
                txt = ""
            up_to_date = out.stat().st_mtime >= ossfuzz_launcher.stat().st_mtime
            has_router = (router_addr in txt) if router_addr else True
            has_harness = (harness_id in txt) if harness_id else True
            # Old wrappers used OSS-Fuzz's `jazzer_agent_deploy.jar` as --agent_path, which disables
            # the atl-jazzer ZMQ Dealer integration. Force regeneration when that is detected.
            has_atl_standalone = ("jazzer_standalone_deploy.jar" in txt) and ("jazzer_agent_deploy.jar" not in txt)
            if up_to_date and has_router and has_harness and has_atl_standalone:
                return out

        cmd = [
            sys.executable,
            str(self.script),
            "--ossfuzz-launcher",
            str(ossfuzz_launcher),
            "--out",
            str(out),
            "--zmq-router-addr",
            router_addr,
            "--zmq-harness-id",
            harness_id,
            "--zmq-dealer-log",
            str(dealer_log),
        ]
        shm_name = self.workdir.read_shm_name()
        if shm_name:
            cmd += ["--zmq-shm-name", shm_name]
        subprocess.check_call(cmd)
        return out
