import os
import time
import shutil
import random
import subprocess
from pathlib import Path
from typing import Optional

from config import Config
from util import ensure_dirs, safe_list_files, sha256_file, atomic_copy_to_dir


def watcher_enqueue_seeds(cfg: Config):
    ensure_dirs(cfg.work_dir)
    corpus = cfg.corpus_dir
    queue = cfg.work_dir / "queue"
    logs = cfg.work_dir / "logs"
    log_path = logs / "watcher.log"

    last_count = len(safe_list_files(corpus))
    last_change = time.time()
    seen_hashes = set()

    def log(msg: str):
        print("[Watcher]", msg)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(msg + "\n")

    log("started")

    while True:
        files = safe_list_files(corpus)
        count = len(files)
        print(count)

        if count > last_count:
            last_count = count
            last_change = time.time()

        if time.time() - last_change >= cfg.plateau_seconds:
            log(f"plateau detected: corpus_count={count}. enqueue {cfg.seeds_per_plateau} seeds.")
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

            head = files[:min(len(files), cfg.seeds_per_plateau * 3)]
            rest = files[min(len(files), cfg.seeds_per_plateau * 3):]
            random.shuffle(rest)
            candidates = head + rest

            enq = 0
            for f in candidates:
                if not f.is_file():
                    continue
                if f.stat().st_size > cfg.max_seed_bytes:
                    continue

                h = sha256_file(f)
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)

                qname = f"{h[:12]}_{f.name}"
                atomic_copy_to_dir(f, queue, qname)
                enq += 1
                log(f"enqueued: {qname} size={f.stat().st_size}")
                if enq >= cfg.seeds_per_plateau:
                    break

            last_change = time.time()

        time.sleep(cfg.check_interval)


def dse_worker(cfg: Config, worker_id: int = 0):
    """
    One worker process: claims seeds from queue, runs wrapper(seed, out_dir),
    imports generated inputs into corpus.

    Safe for multiple workers via atomic rename claim.
    """
    ensure_dirs(cfg.work_dir)
    corpus = cfg.corpus_dir
    queue = cfg.work_dir / "queue"
    inflight = queue / ".inflight"
    out_tmp_root = cfg.work_dir / "generated"
    logs = cfg.work_dir / "logs"

    inflight.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)

    if cfg.dse_backend.lower() == "spf":
        wrapper = cfg.spf_wrapper
    elif cfg.dse_backend.lower() == "swat":
        wrapper = cfg.swat_wrapper
    else:
        wrapper = cfg.dummy_wrapper

    def claim_one_seed() -> Optional[Path]:
        items = safe_list_files(queue)
        # ignore inflight dir entries (safe_list_files already filters files only)
        if not items:
            return None
        items.sort(key=lambda p: p.stat().st_mtime)  # oldest first
        for p in items:
            # attempt atomic claim
            claimed = inflight / f"{p.name}.w{worker_id}.pid{os.getpid()}"
            try:
                os.replace(p, claimed)  # atomic on same filesystem
                return claimed
            except FileNotFoundError:
                continue
            except OSError:
                continue
        return None

    def import_generated(out_tmp: Path) -> int:
        imported = 0

        # 1) corpus existing fingerprints (recent N files)
        corpus_fp = build_dir_fingerprint_index(corpus, limit_files=20000)

        # 2) dedup within this batch
        batch_fp = set()

        # candidates: smaller first (often more useful for parsers), or you can do random
        files = safe_list_files(out_tmp)
        files.sort(key=lambda p: p.stat().st_size)

        for f in files:
            sz = f.stat().st_size

            # ---- size filter ----
            if sz < cfg.min_generated_bytes:
                continue
            if sz > cfg.max_generated_bytes:
                continue

            # ---- fingerprint dedup ----
            fp = fast_fingerprint(f)
            if fp in batch_fp:
                continue
            if fp in corpus_fp:
                continue

            batch_fp.add(fp)

            # ---- name by hash (stable) ----
            name = f"gen_{fp[:16]}_{sz}"
            dst = corpus / name
            if dst.exists():
                continue

            atomic_copy_to_dir(f, corpus, name)
            corpus_fp.add(fp)
            imported += 1

            if imported >= cfg.max_import_per_seed:
                break

        return imported

    print(f"[DSE-{worker_id}] backend={cfg.dse_backend} wrapper={wrapper}")

    while True:
        seed_claimed = claim_one_seed()
        if seed_claimed is None:
            time.sleep(cfg.dse_poll_interval)
            continue

        # per-worker output dir to avoid collisions
        out_tmp = out_tmp_root / f"w{worker_id}"
        shutil.rmtree(out_tmp, ignore_errors=True)
        out_tmp.mkdir(parents=True, exist_ok=True)

        log_path = logs / f"dse_w{worker_id}_{seed_claimed.name}.log"
        cmd = [os.environ.get("PYTHON", "python3"), str(wrapper), str(seed_claimed), str(out_tmp)]
        print(f"[DSE-{worker_id}] running:", " ".join(cmd))

        with log_path.open("w", encoding="utf-8", errors="replace") as lf:
            rc = subprocess.call(cmd, stdout=lf, stderr=subprocess.STDOUT)

        if rc != 0:
            print(f"[DSE-{worker_id}] failed rc={rc} seed={seed_claimed.name}")
        else:
            n = import_generated(out_tmp)
            print(f"[DSE-{worker_id}] imported {n} inputs")

        # done
        try:
            seed_claimed.unlink()
        except FileNotFoundError:
            pass
