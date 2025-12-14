from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

@dataclass
class Config:
    # works
    corpus_dir: Path = None
    work_dir: Path = Path("work")

    # Plateau detection
    plateau_seconds: int = 5 # 300
    check_interval: int = 1 # 20
    seeds_per_plateau: int = 4
    max_seed_bytes: int = 1_000_000


    max_generated_bytes: int = 256 * 1024   # 256KB default
    min_generated_bytes: int = 1            # prevent empty
    max_import_per_seed: int = 64           # seed 하나당 import 상한

    # DSE
    dummy_wrapper: Path = Path("wrappers/dummy_wrapper.py")
    spf_wrapper: Path = Path("wrappers/spf_wrapper.py")
    swat_wrapper: Path = Path("wrappers/swat_wrapper.py")

    # DSE worker behavior
    dse_backend: str = "dummy"
    dse_workers: int = 1
    dse_poll_interval: int = 3  # seconds

    # # fuzzer args if you want to run fuzzer role
    # fuzzer_bin: Optional[Path] = None
    # reload_sec: int = 1
    # artifact_prefix: Optional[str] = None
    # extra_fuzzer_args: Optional[List[str]] = None
