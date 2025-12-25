import multiprocessing
import time
from dataclasses import dataclass
from pathlib import Path

from jfo.config import Config
from jfo.components.atl_jazzer_launcher import AtlJazzerLauncherGenerator
from jfo.components.coverage import CoverageRunner
from jfo.components.dse_worker import dse_worker
from jfo.components.fuzzer import FuzzerRunner
from jfo.components.findings_deduper import run_findings_deduper
from jfo.components.watcher import watcher_enqueue_seeds
from jfo.seed_router import ensure_seed_router_running
from jfo.util.processes import ProcessSupervisor
from jfo.util.workdir import WorkDir


@dataclass(frozen=True, slots=True)
class AllOptions:
    fuzzer_path: Path
    mode: str
    bind: str | None
    no_router: bool
    no_fuzzer: bool
    no_watcher: bool
    no_dse: bool
    coverage: bool
    coverage_runs: int
    max_seconds: int | None
    fuzzer_args: list[str]


class Pipeline:
    def __init__(self, *, cfg: Config, workdir: WorkDir):
        self.cfg = cfg
        self.workdir = workdir
        self.fuzzer = FuzzerRunner(cfg=cfg)
        self.atl_launcher = AtlJazzerLauncherGenerator(workdir=workdir)

    @staticmethod
    def derive_harness_id(launcher_path: Path) -> str:
        return launcher_path.name

    def run_all(self, opt: AllOptions) -> int:
        oss_launcher = opt.fuzzer_path
        harness = self.derive_harness_id(oss_launcher)
        self.cfg.mode = (opt.mode or "default").lower()

        if opt.coverage:
            return CoverageRunner(cfg=self.cfg).run(
                harness=harness,
                launcher=oss_launcher,
                fuzzer_runner=self.fuzzer,
                fuzzer_args=list(opt.fuzzer_args),
                runs=int(opt.coverage_runs or 1),
                max_seconds=opt.max_seconds,
            )

        params = self.workdir.ensure_seed_router_params(bind=opt.bind, harness=harness)
        router_running = None
        if self.cfg.mode == "atl" and (not opt.no_router):
            router_running = ensure_seed_router_running(
                cfg=self.cfg,
                workdir=self.workdir,
                params=params,
                harness=harness,
                explicit_bind=bool(opt.bind),
            )
            params = router_running.params

        fuzzer_launcher = oss_launcher
        if self.cfg.mode == "atl":
            fuzzer_launcher = self.atl_launcher.ensure(
                ossfuzz_launcher=oss_launcher,
                router_addr=params.bind_addr,
                harness_id=harness,
            )
            self.cfg.fuzzer_path = fuzzer_launcher
        else:
            self.cfg.fuzzer_path = oss_launcher

        sup = ProcessSupervisor()
        try:
            if router_running is not None and router_running.proc is not None:
                sup.add("seed-router", router_running.proc)

            print(
                f"[Main] work_dir={self.cfg.work_dir} harness={harness} mode={self.cfg.mode} "
                f"bind={params.bind_addr} shm_name={params.shm_name} corpus={self.cfg.corpus_dir_resolved}"
            )

            if not opt.no_fuzzer:
                fargs = FuzzerRunner.strip_remainder(opt.fuzzer_args)
                sup.add(
                    "fuzzer",
                    self.fuzzer.run(
                        launcher=fuzzer_launcher,
                        fuzzer_args=fargs,
                        log_path=(self.cfg.logs_dir / "fuzzer.log"),
                    ),
                )
                p = multiprocessing.Process(target=run_findings_deduper, args=(self.cfg,), name="findings")
                p.start()
                sup.add("findings", p)

            # The watcher exists to enqueue corpus plateau seeds for DSE.
            if (not opt.no_watcher) and (not opt.no_dse):
                p = multiprocessing.Process(target=watcher_enqueue_seeds, args=(self.cfg,), name="watcher")
                p.start()
                sup.add("watcher", p)

            if not opt.no_dse:
                self._maybe_fail_fast_atl_dealer(harness=harness, sup=sup, opt=opt)
                for wid in range(self.cfg.dse_workers):
                    cfg_child = Config(
                        work_dir=self.cfg.work_dir,
                        dse_backend=self.cfg.dse_backend,
                        dse_workers=1,
                        fuzzer_path=self.cfg.fuzzer_path,
                        mode=self.cfg.mode,
                    )
                    p = multiprocessing.Process(target=dse_worker, args=(cfg_child, wid), name=f"dse[{wid}]")
                    p.start()
                    sup.add(f"dse[{wid}]", p)

            print(f"[Main] started processes={len(sup.children)} (Ctrl+C to stop)")
            deadline = None
            if opt.max_seconds is not None and int(opt.max_seconds) > 0:
                deadline = time.time() + float(opt.max_seconds)
            while True:
                time.sleep(2)
                if deadline is not None and time.time() >= deadline:
                    print(f"[Main] time limit reached: {int(opt.max_seconds)}s (stopping...)")
                    sup.terminate_all(graceful=True)
                    return 0
                for i, (name, p) in enumerate(sup.children):
                    rc = sup.poll(p)
                    if rc is not None:
                        print(f"[Main] child {i} ({name}) exited rc={rc}")
                        sup.terminate_all(graceful=True)
                        raise SystemExit(int(rc or 0))
        except KeyboardInterrupt:
            print("[Main] stopping...")
            sup.terminate_all(graceful=True)
        return 0

    def _maybe_fail_fast_atl_dealer(self, *, harness: str, sup: ProcessSupervisor, opt: AllOptions) -> None:
        if self.cfg.mode != "atl":
            return
        if opt.no_fuzzer:
            return
        dealer_log = (self.cfg.logs_dir / f"dealer_{harness}.log").resolve()
        # Dealer initialization can be slow (especially with `-jobs`, which spawns worker
        # subprocesses after the initial JVM startup). Avoid false positives by waiting longer.
        deadline = time.time() + 30.0
        while time.time() < deadline:
            if dealer_log.exists():
                return
            # Some builds emit the dealer init message before the log file is created.
            try:
                for p in self.cfg.logs_dir.glob("fuzz-*.log"):
                    if p.is_file() and "Initializing OOF mutation dealer" in p.read_text(encoding="utf-8", errors="replace"):
                        return
            except Exception:
                pass
            fuzzer_exited = any((name == "fuzzer" and p.poll() is not None) for name, p in sup.children)
            if fuzzer_exited:
                break
            time.sleep(0.2)

        if not dealer_log.exists():
            print(
                "[Main] error: ZMQ dealer not detected (dealer log not created). "
                "ZMQ-only delivery cannot work without OOFMutate Dealer support in the fuzzer.\n"
                f"  expected dealer log: {dealer_log}\n"
                "Fix options:\n"
                "  - Ensure `--mode atl` is used and the generated wrapper uses atl-jazzer's "
                "`jazzer_standalone_deploy.jar` (not OSS-Fuzz `jazzer_agent_deploy.jar`).\n"
                "  - Check `logs/fuzzer.log` for `[+] Initializing OOF mutation dealer ...`.\n"
                "  - If you don't have Dealer support, use `--mode default` instead.\n"
                "  - Or run without DSE (advanced option: `--no-dse`) until Dealer works."
            )
            sup.terminate_all(graceful=True)
            raise SystemExit(2)
