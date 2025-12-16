import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


_FMT = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


@dataclass(frozen=True)
class RunLog:
    logger: logging.Logger
    stream: TextIO
    path: Path
    _handler: logging.Handler

    def close(self) -> None:
        try:
            self.logger.removeHandler(self._handler)
        except Exception:
            pass
        try:
            self._handler.flush()
        except Exception:
            pass
        try:
            self._handler.close()
        except Exception:
            pass
        try:
            self.stream.flush()
        except Exception:
            pass
        try:
            self.stream.close()
        except Exception:
            pass


def open_run_log(log_path: Path, *, logger_name: str) -> RunLog:
    """
    Open a per-run log file and return a `RunLog` (logger + writable stream).
    The stream can also be used as a sink for subprocess stdout/stderr.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    unique = f"{logger_name}.{os.getpid()}.{int(time.time() * 1000)}"
    logger = logging.getLogger(unique)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    fp = log_path.open("w", encoding="utf-8", errors="replace")
    handler = logging.StreamHandler(fp)
    handler.setFormatter(_FMT)
    logger.addHandler(handler)
    return RunLog(logger=logger, stream=fp, path=log_path, _handler=handler)


def make_file_logger(log_path: Path, *, logger_name: str, append: bool = True) -> logging.Logger:
    """
    Create a logger that writes to a file (append by default).
    Useful for long-running components (e.g., watcher) that keep a single log file open.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    unique = f"{logger_name}.{os.getpid()}.{int(time.time() * 1000)}"
    logger = logging.getLogger(unique)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    mode = "a" if append else "w"
    handler = logging.FileHandler(log_path, mode=mode, encoding="utf-8")
    handler.setFormatter(_FMT)
    logger.addHandler(handler)
    return logger
