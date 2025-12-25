#!/usr/bin/env python3
import argparse
import os
import shutil
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from jfo.components.findings_deduper import rebuild_findings_once
from jfo.config import Config


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Rebuild <work-dir>/findings from existing <work-dir>/logs (no fuzzer rerun).")
    p.add_argument("--work-dir", required=True, help="Work directory root (e.g. ./w2)")
    p.add_argument("--reset", action="store_true", help="Delete <work-dir>/findings before rebuilding")
    args = p.parse_args(argv)

    work_dir = Path(os.path.expanduser(args.work_dir)).resolve()
    cfg = Config(work_dir=work_dir)

    if args.reset:
        shutil.rmtree(cfg.findings_dir, ignore_errors=True)

    rebuild_findings_once(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
