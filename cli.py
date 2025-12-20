import sys
import time
import argparse
import subprocess
import os
import signal
import random
import shlex
import socket
from pathlib import Path

from config import Config
from watcher import watcher_enqueue_seeds
from dse_worker import dse_worker
from util import ensure_dirs

def parse_args():
    """
    Parse CLI with subcommands to keep required arguments discoverable.

    Defaults live in `config.py` and the work-dir layout.
    """
    p = argparse.ArgumentParser("hybrid orchestrator (watcher + DSE workers)")
    p.add_argument("--work-dir", default="work", help="Work directory root (default: work)")

    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("init", help="Create <work-dir> structure (corpus/queue/logs/zmq/etc)")

    sp_watcher = sub.add_parser("watcher", help="Run watcher (plateau detection + enqueue)")

    sp_dse = sub.add_parser("dse", help="Run a single DSE worker")
    sp_dse.add_argument("--worker-id", type=int, default=0, help="Worker id")
    sp_dse.add_argument("--fuzzer-path", default=None, help="(spf backend) Jazzer-style launcher path")
    sp_dse.add_argument("--mode", choices=["default", "atl"], default="default", help=argparse.SUPPRESS)
    sp_dse.add_argument("--dse-backend", choices=["dummy", "spf", "swat"], default=None, help=argparse.SUPPRESS)

    sp_all = sub.add_parser("all", help="Run full pipeline (router + fuzzer + watcher + DSE workers)")
    sp_all.add_argument("--fuzzer-path", required=True, help="Path to an OSS-Fuzz launcher (used for SPF + running the fuzzer)")
    sp_all.add_argument("--mode", choices=["default", "atl"], default="default", help="Pipeline mode (default: default)")
    sp_all.add_argument("--bind", default=None, help=argparse.SUPPRESS)
    sp_all.add_argument("--no-router", action="store_true", help=argparse.SUPPRESS)
    sp_all.add_argument("--no-fuzzer", action="store_true", help=argparse.SUPPRESS)
    sp_all.add_argument("--no-watcher", action="store_true", help=argparse.SUPPRESS)
    sp_all.add_argument("--no-dse", action="store_true", help=argparse.SUPPRESS)
    sp_all.add_argument("--dse-backend", choices=["dummy", "spf", "swat"], default=None, help=argparse.SUPPRESS)
    sp_all.add_argument("--dse-workers", type=int, default=None, help=argparse.SUPPRESS)
    sp_all.add_argument("fuzzer_args", nargs=argparse.REMAINDER, help="Extra args passed to the fuzzer after `--`")

    args = p.parse_args()
    if args.cmd is None:
        p.print_help(sys.stderr)
        raise SystemExit(2)
    return args

def _resolve_path_arg(s: str) -> Path:
    return Path(os.path.expanduser(s)).resolve()


def build_cfg(args) -> Config:
    work_dir = _resolve_path_arg(args.work_dir)
    fuzzer_path = _resolve_path_arg(args.fuzzer_path) if getattr(args, "fuzzer_path", None) else None
    dse_backend = getattr(args, "dse_backend", None) or Config.dse_backend
    dse_workers = getattr(args, "dse_workers", None)
    if dse_workers is None:
        dse_workers = Config.dse_workers
    mode = getattr(args, "mode", None) or Config.mode
    return Config(
        work_dir=work_dir,
        dse_backend=dse_backend,
        dse_workers=int(dse_workers),
        fuzzer_path=fuzzer_path,
        mode=mode,
    )

def _require_spf_fuzzer_path(cfg: Config):
    if (cfg.dse_backend or "").lower() != "spf":
        return
    if cfg.fuzzer_path is None:
        raise SystemExit("[spf] missing `--fuzzer-path` (required when --dse-backend=spf)")
    if not cfg.fuzzer_path.is_file():
        raise SystemExit(f"[spf] fuzzer path not found: {cfg.fuzzer_path}")

def _derive_harness_id(launcher_path: Path) -> str:
    return launcher_path.name


def _strip_argparse_remainder(xs: list[str]) -> list[str]:
    if not xs:
        return []
    return xs[1:] if xs[0] == "--" else xs


def _wrapper_path(work_dir: Path, launcher: Path) -> Path:
    return (work_dir / "fuzzer" / f"atl_{launcher.name}").resolve()

def _work_router_addr_path(work_dir: Path) -> Path:
    return work_dir / "zmq" / "router.addr"


def _work_shm_name_path(work_dir: Path) -> Path:
    return work_dir / "zmq" / "shm.name"


def _read_first_line(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()
    except Exception:
        return None


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _sanitize_id(s: str) -> str:
    out = []
    for ch in (s or ""):
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return ("".join(out)[:80]) or "default"


def _pick_random_tcp_port() -> int:
    # Avoid using Python's socket module here (can be blocked in some sandboxes).
    # We simply try a few random high ports and let the router bind decide.
    return random.randint(20000, 65000)


def _ensure_router_params(*, work_dir: Path, bind: str | None, harness: str) -> tuple[str, str]:
    """
    Return (bind_addr, shm_name).
    If bind is not provided, persist a per-work-dir address under work/zmq/router.addr.
    Always persist a per-work-dir shm name under work/zmq/shm.name.
    """
    if bind:
        bind_addr = str(bind)
    else:
        saved = _read_first_line(_work_router_addr_path(work_dir))
        bind_addr = saved or Config.zmq_router_bind

    shm_saved = _read_first_line(_work_shm_name_path(work_dir))
    if shm_saved:
        shm_name = shm_saved
    else:
        shm_name = f"{Config.zmq_shm_name}-{_sanitize_id(work_dir.name)}-{_sanitize_id(harness)}"
        _write_text_atomic(_work_shm_name_path(work_dir), shm_name + "\n")

    if not bind:
        _write_text_atomic(_work_router_addr_path(work_dir), bind_addr + "\n")
    return bind_addr, shm_name


def _parse_tcp_bind(addr: str) -> tuple[str, int] | None:
    s = (addr or "").strip()
    if not s.startswith("tcp://"):
        return None
    hp = s[len("tcp://") :]
    if not hp or ":" not in hp:
        return None
    host, port_s = hp.rsplit(":", 1)
    host = host.strip() or "0.0.0.0"
    if host == "*":
        host = "0.0.0.0"
    try:
        port = int(port_s)
    except ValueError:
        return None
    return host, port


def _tcp_port_open(host: str, port: int, *, timeout_sec: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_sec):
            return True
    except OSError:
        return False


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


def _terminate_all(children: list[tuple[str, subprocess.Popen]]) -> None:
    for _, p in children:
        _terminate_proc(p)
    for _, p in children:
        try:
            p.wait(timeout=1)
        except Exception:
            pass


def _has_flag(argv: list[str], prefix: str) -> bool:
    for a in argv:
        if a == prefix:
            return True
        if a.startswith(prefix + "="):
            return True
        if a.startswith(prefix + ":"):
            return True
    return False


def _apply_default_fuzzer_args(cfg: Config, fuzzer_args: list[str]) -> list[str]:
    args = list(fuzzer_args)

    if cfg.fuzzer_reload and not _has_flag(args, "-reload"):
        args.append("-reload=1")
    if cfg.fuzzer_reload and cfg.fuzzer_reload_interval > 0 and not _has_flag(args, "-reload_interval"):
        args.append(f"-reload_interval={int(cfg.fuzzer_reload_interval)}")

    if cfg.fuzzer_set_artifact_prefix and not _has_flag(args, "-artifact_prefix"):
        try:
            cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        prefix = str(cfg.artifacts_dir.resolve()) + "/"
        args.append(f"-artifact_prefix={prefix}")

    return args


def _launcher_argv(launcher: Path) -> list[str]:
    """
    Return argv prefix to execute `launcher`.

    Some OSS-Fuzz launchers are root-owned and not executable by the current user, but still
    runnable via their shebang (typically `#!/bin/bash`).
    """
    try:
        if os.access(launcher, os.X_OK):
            return [str(launcher)]
    except Exception:
        pass

    try:
        with launcher.open("r", encoding="utf-8", errors="replace") as f:
            first = f.readline()
    except Exception:
        first = ""

    if first.startswith("#!"):
        shebang = first[2:].strip()
        if shebang:
            return shlex.split(shebang) + [str(launcher)]

    raise SystemExit(f"fuzzer launcher is not executable and has no shebang: {launcher}")


def ensure_atl_wrapper(*, work_dir: Path, ossfuzz_launcher: Path, router_addr: str, harness_id: str) -> Path:
    repo_root = Path(__file__).resolve().parents[0]
    script = (repo_root / "scripts" / "make_atl_jazzer_wrapper_from_ossfuzz.py").resolve()
    if not script.is_file():
        raise SystemExit(f"missing wrapper generator script: {script}")

    out = _wrapper_path(work_dir, ossfuzz_launcher)
    out.parent.mkdir(parents=True, exist_ok=True)
    dealer_log = (work_dir / "logs" / f"dealer_{harness_id}.log").resolve()

    if out.is_file():
        try:
            txt = out.read_text(encoding="utf-8", errors="replace")
        except Exception:
            txt = ""
        up_to_date = out.stat().st_mtime >= ossfuzz_launcher.stat().st_mtime
        has_router = (router_addr in txt) if router_addr else True
        has_harness = (harness_id in txt) if harness_id else True
        # Old wrappers used OSS-Fuzz's `jazzer_agent_deploy.jar` as --agent_path, which disables
        # the atl-jazzer ZMQ Dealer integration. Force regeneration when that is detected.
        has_atl_standalone = ("jazzer_standalone_deploy.jar" in txt) and ("jazzer_agent_deploy.jar" not in txt)
        if up_to_date and has_router and has_harness and has_atl_standalone:
            return out

    cmd = [
        sys.executable,
        str(script),
        "--ossfuzz-launcher",
        str(ossfuzz_launcher),
        "--out",
        str(out),
        "--zmq-router-addr",
        router_addr,
        "--zmq-harness-id",
        harness_id,
        "--zmq-dealer-log",
        str(dealer_log),
    ]
    shm_name = _read_first_line(_work_shm_name_path(work_dir))
    if shm_name:
        cmd += ["--zmq-shm-name", shm_name]
    subprocess.check_call(cmd)
    return out


def run_fuzzer(*, cfg: Config, launcher: Path, fuzzer_args: list[str], log_path: Path) -> subprocess.Popen:
    corpus = cfg.corpus_dir_resolved
    merged = _apply_default_fuzzer_args(cfg, fuzzer_args)
    # libFuzzer generally expects corpus directories after flags.
    cmd = _launcher_argv(launcher) + merged + [str(corpus)]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lf = open(log_path, "ab", buffering=0)
    env = os.environ.copy()
    # Jazzer uses ByteBuddy's Attach API in many builds; ensure the attach socket dir is writable
    # and the attach listener is enabled at JVM startup to avoid runtime self-attach failures.
    tmpdir = (cfg.work_dir / "tmp").resolve()
    try:
        tmpdir.mkdir(parents=True, exist_ok=True)
    except Exception:
        tmpdir = None
    extra_java_opts = []
    if tmpdir is not None:
        extra_java_opts.append(f"-Djava.io.tmpdir={tmpdir}")
    extra_java_opts += ["-Djdk.attach.allowAttachSelf=true", "-XX:+StartAttachListener"]
    prev = env.get("JAVA_TOOL_OPTIONS", "")
    for opt in extra_java_opts:
        if opt not in prev:
            prev = (prev + " " + opt).strip() if prev else opt
    if prev:
        env["JAVA_TOOL_OPTIONS"] = prev
    return subprocess.Popen(
        cmd,
        stdout=lf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        # Keep libFuzzer artifacts under the work-dir by default.
        cwd=str(cfg.work_dir),
        env=env,
    )

def _init_work_dir(args) -> None:
    work_dir = Path(os.path.expanduser(args.work_dir)).resolve()
    ensure_dirs(work_dir)
    (work_dir / "queue" / ".inflight").mkdir(parents=True, exist_ok=True)
    print(f"[Init] ensured work dir: {work_dir}")


def _router_cmd(*, cfg: Config, bind: str, shm_name: str, harness: str) -> list[str]:
    cmd = [
        sys.executable,
        "-m",
        "atl_zmq_router",
        "--bind",
        bind,
        "--harness",
        harness,
        "--work-dir",
        str(cfg.work_dir),
        "--shm-name",
        shm_name,
        "--shm-items",
        str(cfg.zmq_shm_items),
        "--shm-item-size",
        str(cfg.zmq_shm_item_size),
        "--dealer-timeout",
        str(cfg.zmq_dealer_timeout),
        "--ack-timeout",
        str(cfg.zmq_ack_timeout),
        "--poll-interval",
        str(cfg.zmq_poll_interval),
        "--status-interval",
        str(cfg.zmq_status_interval),
        "--script-id",
        str(cfg.zmq_script_id),
        "--log-level",
        cfg.zmq_log_level,
    ]
    if cfg.zmq_delete_processed:
        cmd.append("--delete-processed")
    return cmd


def _maybe_start_router(*, cfg: Config, bind: str, shm_name: str, harness: str, explicit_bind: bool) -> tuple[str, subprocess.Popen | None]:
    """
    Ensure a router is running for (bind, harness, shm_name).
    Returns (effective_bind, proc_or_none).
    If a TCP listener already exists on bind, assumes a router is already running and returns proc=None.
    """
    effective_bind = bind
    for attempt in range(5):
        tcp = _parse_tcp_bind(effective_bind)
        if tcp and _tcp_port_open(tcp[0], tcp[1]):
            print(f"[Main] router bind already in use: {effective_bind}; assuming a router is already running")
            return effective_bind, None

        router_log = cfg.logs_dir / "router.log"
        router_log.parent.mkdir(parents=True, exist_ok=True)
        lf = open(router_log, "ab", buffering=0)
        p = subprocess.Popen(
            _router_cmd(cfg=cfg, bind=effective_bind, shm_name=shm_name, harness=harness),
            stdout=lf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        time.sleep(0.5)
        if p.poll() is None:
            return effective_bind, p

        if explicit_bind:
            raise SystemExit(f"[Main] router failed to start on bind={effective_bind} (rc={p.returncode}); see {router_log}")

        tcp = _parse_tcp_bind(effective_bind)
        host = tcp[0] if tcp else "127.0.0.1"
        effective_bind = f"tcp://{host}:{_pick_random_tcp_port()}"
        _write_text_atomic(_work_router_addr_path(cfg.work_dir), effective_bind + "\n")

        if attempt == 4:
            raise SystemExit(f"[Main] router failed to start after retries; see {router_log}")

    return effective_bind, None


def main():
    args = parse_args()
    if args.cmd == "init":
        _init_work_dir(args)
        return

    cfg = build_cfg(args)
    ensure_dirs(cfg.work_dir)

    if args.cmd in {"dse", "all"}:
        _require_spf_fuzzer_path(cfg)

    if args.cmd == "watcher":
        watcher_enqueue_seeds(cfg)
        return

    if args.cmd == "dse":
        dse_worker(cfg, worker_id=args.worker_id)
        return

    if args.cmd == "all":
        oss_launcher = _resolve_path_arg(args.fuzzer_path)
        harness = _derive_harness_id(oss_launcher)
        cfg.mode = (args.mode or "default").lower()

        bind, shm_name = _ensure_router_params(work_dir=cfg.work_dir, bind=args.bind, harness=harness)
        router_proc = None
        if cfg.mode == "atl" and (not args.no_router):
            bind, router_proc = _maybe_start_router(
                cfg=cfg,
                bind=bind,
                shm_name=shm_name,
                harness=harness,
                explicit_bind=bool(args.bind),
            )

        fuzzer_launcher = oss_launcher
        if cfg.mode == "atl":
            fuzzer_launcher = ensure_atl_wrapper(
                work_dir=cfg.work_dir,
                ossfuzz_launcher=oss_launcher,
                router_addr=bind,
                harness_id=harness,
            )
            cfg.fuzzer_path = fuzzer_launcher
        else:
            cfg.fuzzer_path = oss_launcher

        base = [sys.executable, "-m", "cli", "--work-dir", str(cfg.work_dir)]

        children: list[tuple[str, subprocess.Popen]] = []
        try:
            if router_proc is not None:
                children.append(("router", router_proc))

            print(f"[Main] work_dir={cfg.work_dir} harness={harness} mode={cfg.mode} bind={bind} shm_name={shm_name} corpus={cfg.corpus_dir_resolved}")

            if not args.no_fuzzer:
                fargs = _strip_argparse_remainder(list(args.fuzzer_args))
                children.append(
                    ("fuzzer", run_fuzzer(cfg=cfg, launcher=fuzzer_launcher, fuzzer_args=fargs, log_path=(cfg.logs_dir / "fuzzer.log")))
                )

            if not args.no_watcher:
                children.append(("watcher", subprocess.Popen(base + ["watcher"], start_new_session=True)))

            if not args.no_dse:
                # ATL mode requires a Dealer inside the fuzzer (OOFMutate). If no dealer shows up,
                # running DSE just piles up seeds in <work-dir>/zmq/seeds without ever being consumed.
                if (cfg.mode == "atl") and (not args.no_fuzzer):
                    dealer_log = (cfg.logs_dir / f"dealer_{harness}.log").resolve()
                    deadline = time.time() + 8.0
                    while time.time() < deadline:
                        if dealer_log.exists():
                            break
                        # If the fuzzer crashed early (e.g., agent attach failure), don't wait forever.
                        fuzzer_exited = any((name == "fuzzer" and p.poll() is not None) for name, p in children)
                        if fuzzer_exited:
                            break
                        time.sleep(0.2)
                    if not dealer_log.exists():
                        print(
                            "[Main] error: ZMQ dealer not detected (dealer log not created). "
                            "ZMQ-only delivery cannot work without OOFMutate Dealer support in the fuzzer.\n"
                            f"  expected dealer log: {dealer_log}\n"
                            "Fix options:\n"
                            "  - Ensure `--mode atl` is used and the generated wrapper uses atl-jazzer's "
                            "`jazzer_standalone_deploy.jar` (not OSS-Fuzz `jazzer_agent_deploy.jar`).\n"
                            "  - Check `logs/fuzzer.log` for `[+] Initializing OOF mutation dealer ...`.\n"
                            "  - If you don't have Dealer support, use `--mode default` instead.\n"
                            "  - Or run without DSE (advanced option: `--no-dse`) until Dealer works."
                        )
                        _terminate_all(children)
                        raise SystemExit(2)

                for wid in range(cfg.dse_workers):
                    dse_cmd = base + ["dse", "--worker-id", str(wid), "--mode", cfg.mode, "--dse-backend", str(cfg.dse_backend)]
                    if cfg.fuzzer_path is not None:
                        dse_cmd += ["--fuzzer-path", str(cfg.fuzzer_path)]
                    children.append(
                        (
                            f"dse[{wid}]",
                            subprocess.Popen(dse_cmd, start_new_session=True),
                        )
                    )

            print(f"[Main] started processes={len(children)} (Ctrl+C to stop)")
            while True:
                time.sleep(2)
                for i, (name, p) in enumerate(children):
                    if p.poll() is not None:
                        print(f"[Main] child {i} ({name}) exited rc={p.returncode}")
                        _terminate_all(children)
                        raise SystemExit(int(p.returncode or 0))
        except KeyboardInterrupt:
            print("[Main] stopping...")
            _terminate_all(children)
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
