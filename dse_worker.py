import os
import time
import shutil
import subprocess
from pathlib import Path

from config import Config
from util import ensure_dirs, claim_one_seed, import_generated


class DSEWorker:
    def __init__(self, cfg: Config, worker_id: int = 0):
        self.cfg = cfg
        self.worker_id = worker_id
        ensure_dirs(cfg.work_dir)
        self.corpus = cfg.corpus_dir
        self.queue = cfg.queue_dir
        self.inflight = cfg.inflight_dir
        self.out_tmp_root = cfg.generated_dir
        self.logs = cfg.logs_dir
        self.engine = cfg.engine_path
        self.inflight.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)

    def run(self):
        wid = self.worker_id
        print(f"[DSE-{wid}] backend={self.cfg.dse_backend} engine={self.engine}")
        while True:
            seed_claimed = claim_one_seed(self.queue, self.inflight, self.worker_id)
            if seed_claimed is None:
                time.sleep(self.cfg.dse_poll_interval)
                continue

            out_tmp = self.out_tmp_root / f"w{wid}"
            shutil.rmtree(out_tmp, ignore_errors=True)
            out_tmp.mkdir(parents=True, exist_ok=True)

            log_path = self.logs / f"dse_w{wid}_{seed_claimed.name}.log"
            cmd = [os.environ.get("PYTHON", "python3"), str(self.engine), str(seed_claimed), str(out_tmp)]
            print(f"[DSE-{wid}] running:", " ".join(cmd))
            with log_path.open("w", encoding="utf-8", errors="replace") as lf:
                rc = subprocess.call(cmd, stdout=lf, stderr=subprocess.STDOUT)
            if rc != 0:
                print(f"[DSE-{wid}] failed rc={rc} seed={seed_claimed.name}")
            else:
                n = import_generated(
                    out_tmp,
                    self.corpus,
                    self.cfg.min_generated_bytes,
                    self.cfg.max_generated_bytes,
                    self.cfg.max_import_per_seed,
                )
                print(f"[DSE-{wid}] imported {n} inputs")

            try:
                seed_claimed.unlink()
            except FileNotFoundError:
                pass


def dse_worker(cfg: Config, worker_id: int = 0):
    DSEWorker(cfg, worker_id).run()
