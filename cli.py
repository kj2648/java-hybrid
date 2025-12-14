import sys
import time
import argparse
import subprocess
from pathlib import Path

from config import Config
from roles import watcher_enqueue_seeds, dse_worker

def parse_args():
    p = argparse.ArgumentParser("hybrid orchestrator (watcher + multi DSE workers)")
    p.add_argument("--corpus", required=True)
    p.add_argument("--work-dir", default="work", help="Work directory root")
    p.add_argument("--dse-backend", choices=["dummy", "spf", "swat"], default="dummy")

    p.add_argument("--plateau-seconds", type=int, default=20)
    p.add_argument("--check-interval", type=int, default=5)
    p.add_argument("--seeds-per-plateau", type=int, default=4)
    p.add_argument("--max-seed-bytes", type=int, default=1_000_000)

    p.add_argument("--dse-workers", type=int, default=1, help="Number of parallel DSE workers")
    p.add_argument("--dse-poll-interval", type=int, default=3)

    p.add_argument("role", choices=["watcher", "dse", "all"], help="Which role to run")
    p.add_argument("--worker-id", type=int, default=0, help="(internal) worker id for role=dse")
    return p.parse_args()

def build_cfg(args) -> Config:
    return Config(
        corpus_dir=Path(args.corpus).resolve(),
        work_dir=Path(args.work_dir).resolve(),
        plateau_seconds=args.plateau_seconds,
        check_interval=args.check_interval,
        seeds_per_plateau=args.seeds_per_plateau,
        max_seed_bytes=args.max_seed_bytes,
        dse_backend=args.dse_backend,
        dse_workers=args.dse_workers,
        dse_poll_interval=args.dse_poll_interval,
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
        "--plateau-seconds", str(args.plateau_seconds),
        "--check-interval", str(args.check_interval),
        "--seeds-per-plateau", str(args.seeds_per_plateau),
        "--max-seed-bytes", str(args.max_seed_bytes),
        "--dse-workers", str(args.dse_workers),
        "--dse-poll-interval", str(args.dse_poll_interval),
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
