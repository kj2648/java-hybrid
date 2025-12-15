import time
from pathlib import Path

from config import Config
from util import ensure_dirs, safe_list_files, sha256_file, atomic_copy_to_dir, pick_candidates


class Watcher:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        ensure_dirs(cfg.work_dir)
        self.corpus: Path = cfg.corpus_dir
        self.queue: Path = cfg.queue_dir
        self.logs: Path = cfg.logs_dir
        self.log_path: Path = self.logs / "watcher.log"
        self.last_count = len(safe_list_files(self.corpus))
        self.last_change = time.time()
        self.seen_hashes = set()

    def log(self, msg: str):
        print("[Watcher]", msg)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def enqueue_from_plateau(self, files: list[Path]):
        enq = 0
        for f in files:
            if not f.is_file():
                continue
            if f.stat().st_size > self.cfg.max_seed_bytes:
                continue
            h = sha256_file(f)
            if h in self.seen_hashes:
                continue
            self.seen_hashes.add(h)
            qname = f"{h[:12]}_{f.name}"
            atomic_copy_to_dir(f, self.queue, qname)
            enq += 1
            self.log(f"enqueued: {qname} size={f.stat().st_size}")
            if enq >= self.cfg.seeds_per_plateau:
                break

    def run(self):
        self.logs.mkdir(parents=True, exist_ok=True)
        self.log("started")
        while True:
            files = safe_list_files(self.corpus)
            count = len(files)
            print(count)
            if count > self.last_count:
                self.last_count = count
                self.last_change = time.time()
            if time.time() - self.last_change >= self.cfg.plateau_seconds:
                self.log(
                    f"plateau detected: corpus_count={count}. enqueue {self.cfg.seeds_per_plateau} seeds."
                )
                files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                self.enqueue_from_plateau(
                    pick_candidates(files, self.cfg.seeds_per_plateau * 3)
                )
                self.last_change = time.time()
            time.sleep(self.cfg.check_interval)


def watcher_enqueue_seeds(cfg: Config):
    Watcher(cfg).run()

