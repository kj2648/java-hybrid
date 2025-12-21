"""
Lifecycle management for child processes (subprocess + multiprocessing).
"""

import os
import signal
import subprocess
import multiprocessing
from dataclasses import dataclass, field


def _terminate_proc(p: subprocess.Popen, *, timeout_sec: float = 5.0) -> None:
    if p.poll() is not None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except Exception:
        pass
    try:
        p.terminate()
    except Exception:
        pass
    try:
        p.wait(timeout=timeout_sec)
        return
    except Exception:
        pass
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        p.kill()
    except Exception:
        pass


@dataclass(slots=True)
class ProcessSupervisor:
    children: list[tuple[str, object]] = field(default_factory=list)

    def add(self, name: str, proc: object) -> None:
        self.children.append((name, proc))

    @staticmethod
    def poll(proc: object) -> int | None:
        if isinstance(proc, subprocess.Popen):
            return proc.poll()
        if isinstance(proc, multiprocessing.Process):
            return proc.exitcode
        return None

    def terminate_all(self) -> None:
        # Terminate Popen processes first (they may own process groups).
        for _, p in self.children:
            if isinstance(p, subprocess.Popen):
                _terminate_proc(p)

        for _, p in self.children:
            if isinstance(p, multiprocessing.Process):
                try:
                    if p.is_alive():
                        p.terminate()
                except Exception:
                    pass

        for _, p in self.children:
            try:
                if isinstance(p, subprocess.Popen):
                    p.wait(timeout=1)
                elif isinstance(p, multiprocessing.Process):
                    p.join(timeout=1)
            except Exception:
                pass
