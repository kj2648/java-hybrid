import argparse
import os
from pathlib import Path

from jfo.config import Config
from jfo.pipeline import AllOptions, Pipeline
from jfo.util.workdir import WorkDir


class App:
    def build_parser(self) -> argparse.ArgumentParser:
        p = argparse.ArgumentParser("JFO (Java Fuzz Orchestrator)")
        p.add_argument("--work-dir", default="work", help="Work directory root (default: work)")
        p.add_argument("--fuzzer-path", required=True, help="Path to an OSS-Fuzz launcher (used for SPF + running the fuzzer)")
        p.add_argument("--mode", choices=["default", "atl"], default="default", help="Pipeline mode (default: default)")
        p.add_argument("--bind", default=None, help=argparse.SUPPRESS)
        p.add_argument("--no-router", action="store_true", help=argparse.SUPPRESS)
        p.add_argument("--no-fuzzer", action="store_true", help=argparse.SUPPRESS)
        p.add_argument("--no-watcher", action="store_true", help=argparse.SUPPRESS)
        p.add_argument("--no-dse", action="store_true", help=argparse.SUPPRESS)
        p.add_argument("--dse-backend", choices=["dummy", "spf", "gdart", "swat"], default=None, help=argparse.SUPPRESS)
        p.add_argument("--dse-workers", type=int, default=None, help=argparse.SUPPRESS)
        p.add_argument("fuzzer_args", nargs=argparse.REMAINDER, help="Extra args passed to the fuzzer after `--`")

        return p

    def run(self, argv: list[str] | None = None) -> int:
        parser = self.build_parser()
        args = parser.parse_args(argv)

        work_dir = Path(os.path.expanduser(args.work_dir)).resolve()
        workdir = WorkDir(work_dir)
        workdir.ensure()

        cfg = self._build_cfg(args, work_dir=work_dir)
        self._require_spf_fuzzer_path(cfg)

        opt = AllOptions(
            fuzzer_path=Path(args.fuzzer_path).expanduser().resolve(),
            mode=args.mode,
            bind=getattr(args, "bind", None),
            no_router=getattr(args, "no_router", False),
            no_fuzzer=getattr(args, "no_fuzzer", False),
            no_watcher=getattr(args, "no_watcher", False),
            no_dse=getattr(args, "no_dse", False),
            fuzzer_args=list(getattr(args, "fuzzer_args", [])),
        )
        return Pipeline(cfg=cfg, workdir=workdir).run_all(opt)

    def _build_cfg(self, args, *, work_dir: Path) -> Config:
        fuzzer_path = Path(os.path.expanduser(args.fuzzer_path)).resolve() if getattr(args, "fuzzer_path", None) else None
        dse_backend = getattr(args, "dse_backend", None) or Config.dse_backend
        dse_workers = getattr(args, "dse_workers", None)
        if dse_workers is None:
            dse_workers = Config.dse_workers
        mode = getattr(args, "mode", None) or Config.mode
        return Config(
            work_dir=work_dir,
            dse_backend=dse_backend,
            dse_workers=int(dse_workers),
            fuzzer_path=fuzzer_path,
            mode=mode,
        )

    @staticmethod
    def _require_spf_fuzzer_path(cfg: Config) -> None:
        if (cfg.dse_backend or "").lower() != "spf":
            return
        if cfg.fuzzer_path is None:
            raise SystemExit("[spf] missing `--fuzzer-path` (required when --dse-backend=spf)")
        if not cfg.fuzzer_path.is_file():
            raise SystemExit(f"[spf] fuzzer path not found: {cfg.fuzzer_path}")
