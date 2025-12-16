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
    dummy_engine: Path = Path("engines/dummy_engine.py")
    spf_engine: Path = Path("engines/spf_engine.py")
    swat_engine: Path = Path("engines/swat_engine.py")
    fuzzer_path: Optional[Path] = None

    # DSE worker behavior
    dse_backend: str = "dummy"
    dse_workers: int = 1
    dse_poll_interval: int = 3  # seconds
    dse_timeout_sec: int = 60   # kill hung engine runs

    # # fuzzer args if you want to run fuzzer role
    # fuzzer_bin: Optional[Path] = None
    # reload_sec: int = 1
    # artifact_prefix: Optional[str] = None
    # extra_fuzzer_args: Optional[List[str]] = None

    # -------- Derived paths / helpers (read-only) --------
    @property
    def queue_dir(self) -> Path:
        return self.work_dir / "queue"

    @property
    def inflight_dir(self) -> Path:
        return self.queue_dir / ".inflight"

    @property
    def logs_dir(self) -> Path:
        return self.work_dir / "logs"

    @property
    def generated_dir(self) -> Path:
        return self.work_dir / "generated"

    @property
    def engine_path(self) -> Path:
        b = (self.dse_backend or "").lower()
        if b == "spf":
            return self.spf_engine
        if b == "swat":
            return self.swat_engine
        return self.dummy_engine
