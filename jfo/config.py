from dataclasses import dataclass
from pathlib import Path

@dataclass
class Config:
    # works
    work_dir: Path = Path("work")

    # Plateau detection
    plateau_seconds: int = 20 # 300
    check_interval: int = 5 # 20
    seeds_per_plateau: int = 2
    max_seed_bytes: int = 1_000_000


    max_generated_bytes_corpus: int = 256 * 1024   # 256KB default
    max_generated_bytes_zmq: int = 32 * 1024 - 4   # should be <= zmq_max_payload_bytes
    min_generated_bytes: int = 1            # prevent empty
    max_import_per_seed: int = 64           # seed 하나당 import 상한

    # DSE
    dummy_engine: Path = Path("engines/dummy_engine.py")
    spf_engine: Path = Path("engines/spf_engine.py")
    swat_engine: Path = Path("engines/swat_engine.py")
    fuzzer_path: Path | None = None

    # DSE worker behavior
    dse_backend: str = "spf"
    dse_workers: int = 1
    dse_poll_interval: int = 3  # seconds
    dse_timeout_sec: int = 60   # kill hung engine runs

    # Mode:
    # - default: DSE outputs go to <work-dir>/corpus (fuzzer consumes via corpus reload)
    # - atl:     DSE outputs go to <work-dir>/zmq/seeds (fuzzer consumes via ZMQ Dealer/OOFMutate)
    mode: str = "default"

    # ZMQ seed-router defaults (for `python3 -m jfo.seed_router`)
    zmq_router_bind: str = "tcp://127.0.0.1:5555"
    zmq_shm_name: str = "atl-jazzer-shm"
    zmq_shm_items: int = 1024
    zmq_shm_item_size: int = 32 * 1024  # includes 4B length field
    zmq_dealer_timeout: int = 10
    zmq_ack_timeout: int = 30
    zmq_poll_interval: float = 0.25
    zmq_status_interval: float = 5.0
    zmq_script_id: int = 1
    zmq_delete_processed: bool = False
    zmq_log_level: str = "INFO"

    # Fuzzer runtime behavior (libFuzzer/Jazzer)
    # `-reload=1` makes libFuzzer periodically reload corpus dirs from disk, which is useful
    # when other processes (e.g., DSE worker) add new inputs into the corpus during a run.
    fuzzer_reload: bool = True
    # Not all Jazzer/libFuzzer builds support `-reload_interval`; keep disabled by default.
    fuzzer_reload_interval: int = 0

    # Keep artifacts (crashes/leaks) under <work-dir>/artifacts unless user overrides.
    fuzzer_set_artifact_prefix: bool = True

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
    def artifacts_dir(self) -> Path:
        return self.work_dir / "artifacts"

    @property
    def corpus_dir_resolved(self) -> Path:
        return self.work_dir / "corpus"

    @property
    def zmq_seeds_dir(self) -> Path:
        return self.work_dir / "zmq" / "seeds"

    @property
    def zmq_max_payload_bytes(self) -> int:
        # The seed-router shared memory item size reserves 4 bytes for payload length.
        return max(0, int(self.zmq_shm_item_size) - 4)

    @property
    def engine_path(self) -> Path:
        b = (self.dse_backend or "").lower()
        if b == "spf":
            return self.spf_engine
        if b == "swat":
            return self.swat_engine
        return self.dummy_engine
