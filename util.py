import os
import shutil
import hashlib
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