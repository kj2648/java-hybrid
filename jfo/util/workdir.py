import os
from dataclasses import dataclass
from pathlib import Path

from jfo.config import Config
from jfo.util.fs import ensure_dirs


@dataclass(frozen=True, slots=True)
class SeedRouterParams:
    bind_addr: str
    shm_name: str


@dataclass(frozen=True, slots=True)
class WorkDir:
    root: Path

    def ensure(self) -> None:
        ensure_dirs(self.root)
        (self.root / "queue" / ".inflight").mkdir(parents=True, exist_ok=True)

    @property
    def seed_router_addr_file(self) -> Path:
        return self.root / "zmq" / "router.addr"

    @property
    def seed_router_shm_name_file(self) -> Path:
        return self.root / "zmq" / "shm.name"

    def ensure_seed_router_params(self, *, bind: str | None, harness: str) -> SeedRouterParams:
        if bind:
            bind_addr = str(bind)
        else:
            bind_addr = self._read_first_line(self.seed_router_addr_file) or Config.zmq_router_bind

        shm_name = self._read_first_line(self.seed_router_shm_name_file)
        if not shm_name:
            shm_name = f"{Config.zmq_shm_name}-{self._sanitize_id(self.root.name)}-{self._sanitize_id(harness)}"
            self._write_text_atomic(self.seed_router_shm_name_file, shm_name + "\n")

        if not bind:
            self._write_text_atomic(self.seed_router_addr_file, bind_addr + "\n")

        return SeedRouterParams(bind_addr=bind_addr, shm_name=shm_name)

    def persist_seed_router_bind(self, bind_addr: str) -> None:
        self._write_text_atomic(self.seed_router_addr_file, bind_addr + "\n")

    def read_shm_name(self) -> str | None:
        return self._read_first_line(self.seed_router_shm_name_file)

    @staticmethod
    def _read_first_line(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()
        except Exception:
            return None

    @staticmethod
    def _write_text_atomic(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)

    @staticmethod
    def _sanitize_id(s: str) -> str:
        out = []
        for ch in (s or ""):
            if ch.isalnum() or ch in ("-", "_", "."):
                out.append(ch)
            else:
                out.append("_")
        return ("".join(out)[:80]) or "default"
