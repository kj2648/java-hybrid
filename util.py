import os
import shutil
import hashlib
import random
from pathlib import Path
from typing import List, Set, Optional

def ensure_dirs(work_dir: Path):
    (work_dir / "queue").mkdir(parents=True, exist_ok=True)
    (work_dir / "generated").mkdir(parents=True, exist_ok=True)
    (work_dir / "logs").mkdir(parents=True, exist_ok=True)

def safe_list_files(d: Path) -> List[Path]:
    if not d.exists():
        return []
    return [p for p in d.iterdir() if p.is_file()]

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def atomic_copy_to_dir(src: Path, dst_dir: Path, name: Optional[str] = None) -> Path:
    dst_dir.mkdir(parents=True, exist_ok=True)
    if name is None:
        name = src.name
    tmp = dst_dir / (name + ".tmp")
    dst = dst_dir / name
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)
    return dst

def fast_fingerprint(p: Path, sample: int = 4096) -> str:
    """
    Faster than full sha256 for big files:
    hash(prefix + suffix + size)
    """
    size = p.stat().st_size
    h = hashlib.sha256()
    with p.open("rb") as f:
        h.update(f.read(sample))
        if size > sample:
            try:
                f.seek(max(0, size - sample))
                h.update(f.read(sample))
            except Exception:
                pass
    h.update(str(size).encode())
    return h.hexdigest()

def build_dir_fingerprint_index(dirpath: Path, limit_files: int = 20000) -> Set[str]:
    """
    Build fingerprint set for existing corpus to dedup imports.
    limit_files avoids huge scans if corpus is enormous.
    """
    fps = set()
    if not dirpath.exists():
        return fps
    files = [p for p in dirpath.iterdir() if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files[:min(len(files), limit_files)]:
        try:
            fps.add(fast_fingerprint(p))
        except Exception:
            continue
    return fps


def claim_one_seed(queue: Path, inflight: Path, worker_id: int) -> Optional[Path]:
    """
    Atomically claim the oldest seed file in queue by moving it into inflight.
    Returns the claimed path (now under inflight) or None if nothing to claim.
    """
    items = safe_list_files(queue)
    if not items:
        return None
    items.sort(key=lambda p: p.stat().st_mtime)  # oldest first
    for p in items:
        claimed = inflight / f"{p.name}.w{worker_id}.pid{os.getpid()}"
        try:
            os.replace(p, claimed)
            return claimed
        except (FileNotFoundError, OSError):
            continue
    return None


def import_generated(out_tmp: Path, corpus: Path,
                     min_bytes: int, max_bytes: int, max_import: int) -> int:
    """
    Import generated inputs from out_tmp into corpus with size caps and fast dedup.
    Returns number of imported files.
    """
    imported = 0
    corpus_fp = build_dir_fingerprint_index(corpus, limit_files=20000)
    batch_fp: Set[str] = set()

    files = safe_list_files(out_tmp)
    files.sort(key=lambda p: p.stat().st_size)
    for f in files:
        sz = f.stat().st_size
        if sz < min_bytes or sz > max_bytes:
            continue
        fp = fast_fingerprint(f)
        if fp in batch_fp or fp in corpus_fp:
            continue
        batch_fp.add(fp)

        name = f"gen_{fp[:16]}_{sz}"
        dst = corpus / name
        if dst.exists():
            continue

        atomic_copy_to_dir(f, corpus, name)
        corpus_fp.add(fp)
        imported += 1
        if imported >= max_import:
            break
    return imported


def pick_candidates(files: List[Path], head_count: int) -> List[Path]:
    """
    Take newest head_count files and shuffle the rest for variety.
    """
    head = files[:min(len(files), head_count)]
    rest = files[min(len(files), head_count):]
    random.shuffle(rest)
    return head + rest
