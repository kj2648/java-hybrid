import sys
import time
import argparse
import subprocess
from pathlib import Path

from config import Config
from watcher import watcher_enqueue_seeds
from dse_worker import dse_worker

def parse_args():
    """Parse minimal CLI, rely on config for rarely-changed values."""
    p = argparse.ArgumentParser("hybrid orchestrator (watcher + DSE workers)")
    p.add_argument("--corpus", required=True, help="Path to corpus directory")
    p.add_argument("--work-dir", required=True, help="Work directory root")
    p.add_argument("--dse-backend", choices=["dummy", "spf", "swat"], required=True, help="DSE backend engine")
    p.add_argument("--dse-workers", type=int, default=Config.dse_workers, help="Number of DSE workers")

    # role selection
    p.add_argument("role", choices=["watcher", "dse", "all"], help="Which role to run")
    p.add_argument("--worker-id", type=int, default=0, help="(internal) worker id for role=dse")
    return p.parse_args()

def build_cfg(args) -> Config:
    return Config(
        corpus_dir=Path(args.corpus).resolve(),
        work_dir=Path(args.work_dir).resolve(),
        dse_backend=args.dse_backend,
        dse_workers=args.dse_workers,
    )

def spawn_all(args):
    """
    spawn watcher + N workers
    """
    base = [
        sys.executable, "-m", "cli",
        "--corpus", args.corpus,
        "--work-dir", args.work_dir,
        "--dse-backend", args.dse_backend,
        "--dse-workers", str(args.dse_workers),
    ]

    procs = []
    procs.append(subprocess.Popen(base + ["watcher"]))
    for wid in range(args.dse_workers):
        procs.append(subprocess.Popen(base + ["dse", "--worker-id", str(wid)]))

    print(f"[Main] started watcher + {args.dse_workers} dse workers (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(5)
            for i, p in enumerate(procs):
                if p.poll() is not None:
                    print(f"[Main] child {i} exited rc={p.returncode}")
                    return
    except KeyboardInterrupt:
        print("[Main] stopping...")
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()

def main():
    args = parse_args()
    cfg = build_cfg(args)

    if args.role == "watcher":
        watcher_enqueue_seeds(cfg)
    elif args.role == "dse":
        dse_worker(cfg, worker_id=args.worker_id)
    elif args.role == "all":
        spawn_all(args)

if __name__ == "__main__":
    main()
