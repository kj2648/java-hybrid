"""
Lifecycle management for child processes (subprocess + multiprocessing).
"""

import os
import signal
import subprocess
import multiprocessing
from dataclasses import dataclass, field


def _send_group_signal(p: subprocess.Popen, sig: int) -> None:
    if p.poll() is not None:
        return
    try:
        os.killpg(p.pid, sig)
        return
    except Exception:
        pass
    try:
        os.kill(p.pid, sig)
    except Exception:
        pass


def _stop_popen(
    p: subprocess.Popen,
    *,
    first_sig: int = signal.SIGTERM,
    first_timeout_sec: float = 5.0,
    second_sig: int = signal.SIGKILL,
    second_timeout_sec: float = 1.0,
) -> None:
    if p.poll() is not None:
        return
    try:
        _send_group_signal(p, first_sig)
        if first_sig == signal.SIGTERM:
            try:
                p.terminate()
            except Exception:
                pass
        p.wait(timeout=first_timeout_sec)
        return
    except Exception:
        pass
    try:
        _send_group_signal(p, second_sig)
        if second_sig == signal.SIGKILL:
            try:
                p.kill()
            except Exception:
                pass
        p.wait(timeout=second_timeout_sec)
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

    def terminate_all(self, *, graceful: bool = False) -> None:
        popens: list[tuple[str, subprocess.Popen]] = [
            (name, p) for (name, p) in self.children if isinstance(p, subprocess.Popen)
        ]
        mprocs: list[tuple[str, multiprocessing.Process]] = [
            (name, p) for (name, p) in self.children if isinstance(p, multiprocessing.Process)
        ]

        def popen_order_key(item: tuple[str, subprocess.Popen]) -> tuple[int, str]:
            name, _ = item
            if name == "fuzzer":
                return (0, name)
            if name in {"seed-router", "router"}:
                return (2, name)
            return (1, name)

        popens.sort(key=popen_order_key)

        # Stop the fuzzer first. Killing the seed-router before the fuzzer can make libFuzzer/Jazzer
        # report a scary (but meaningless) "fuzz target exited" message on normal shutdown.
        for name, p in popens:
            if graceful and name == "fuzzer":
                _stop_popen(
                    p,
                    first_sig=signal.SIGINT,
                    first_timeout_sec=6.0,
                    second_sig=signal.SIGTERM,
                    second_timeout_sec=2.0,
                )
                _stop_popen(p, first_sig=signal.SIGKILL, first_timeout_sec=1.0)
            elif graceful and name in {"seed-router", "router"}:
                _stop_popen(p, first_sig=signal.SIGINT, first_timeout_sec=2.0, second_sig=signal.SIGTERM)
                _stop_popen(p, first_sig=signal.SIGKILL, first_timeout_sec=1.0)
            else:
                _stop_popen(p)

        for _, p in mprocs:
            if isinstance(p, multiprocessing.Process):
                try:
                    if p.is_alive():
                        p.terminate()
                except Exception:
                    pass

        for _, p in popens:
            try:
                p.wait(timeout=1)
            except Exception:
                pass

        for _, p in mprocs:
            try:
                p.join(timeout=1)
            except Exception:
                pass
