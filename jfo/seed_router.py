#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import os
import random
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from multiprocessing.shared_memory import SharedMemory
from pathlib import Path
from typing import Optional

import zmq
import zmq.asyncio

from jfo.config import Config
from jfo.util.workdir import SeedRouterParams, WorkDir

logger = logging.getLogger("zmq-seed-router")

_HEADER_FMT = "<II"  # item_size:uint32, item_num:uint32
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 8
_LEN_FMT = "<I"  # payload length:uint32
_LEN_SIZE = struct.calcsize(_LEN_FMT)  # 4


@dataclass(frozen=True, slots=True)
class SeedRouterRunning:
    params: SeedRouterParams
    proc: subprocess.Popen | None


def _pick_random_tcp_port() -> int:
    return random.randint(20000, 65000)


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


def _seed_router_cmd(*, cfg: Config, bind: str, shm_name: str, harness: str) -> list[str]:
    cmd = [
        sys.executable,
        "-m",
        "jfo.seed_router",
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


def ensure_seed_router_running(
    *,
    cfg: Config,
    workdir: WorkDir,
    params: SeedRouterParams,
    harness: str,
    explicit_bind: bool,
) -> SeedRouterRunning:
    """
    Ensure a seed-router is running for the work-dir's seed feed.

    Returns (effective params, proc). If the TCP bind is already in use and no explicit bind was given,
    we retry with a random port and persist it into the work-dir so the fuzzer wrapper uses the same bind.
    """
    effective = params
    for attempt in range(5):
        tcp = _parse_tcp_bind(effective.bind_addr)
        router_log = cfg.logs_dir / "router.log"
        router_log.parent.mkdir(parents=True, exist_ok=True)
        lf = open(router_log, "ab", buffering=0)
        p = subprocess.Popen(
            _seed_router_cmd(cfg=cfg, bind=effective.bind_addr, shm_name=effective.shm_name, harness=harness),
            stdout=lf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        time.sleep(0.5)
        if p.poll() is None:
            return SeedRouterRunning(params=effective, proc=p)

        if explicit_bind:
            raise SystemExit(
                f"[Main] seed-router failed to start on bind={effective.bind_addr} (rc={p.returncode}); see {router_log}"
            )

        host = tcp[0] if tcp else "127.0.0.1"
        new_bind = f"tcp://{host}:{_pick_random_tcp_port()}"
        print(
            f"[Main] seed-router failed to start on bind={effective.bind_addr} (rc={p.returncode}); "
            f"retrying with bind={new_bind}"
        )
        workdir.persist_seed_router_bind(new_bind)
        effective = SeedRouterParams(bind_addr=new_bind, shm_name=effective.shm_name)
        if attempt == 4:
            raise SystemExit(f"[Main] seed-router failed to start after retries; see {router_log}")

    return SeedRouterRunning(params=effective, proc=None)


class SeedShmemPoolProducer:
    """
    Shared memory layout (compatible with atl-jazzer Dealer C++ consumer):
      Header(8B) : <item_size:uint32><item_num:uint32> (little-endian)
      Item[i]    : <data_len:uint32><payload bytes..> (max item_size-4)
    """

    def __init__(
        self,
        *,
        shm_name: str,
        item_num: int,
        item_size: int,
        force_recreate: bool,
    ):
        if not shm_name:
            raise ValueError("shm_name is required")
        if item_num <= 0:
            raise ValueError("item_num must be > 0")
        if item_size <= _LEN_SIZE:
            raise ValueError("item_size must be > 4")

        self.shm_name = shm_name
        self.item_num = item_num
        self.item_size = item_size
        self._create_shared_memory(force_recreate=force_recreate)
        self.unassigned = set(range(self.item_num))

    def _create_shared_memory(self, *, force_recreate: bool) -> None:
        total_size = _HEADER_SIZE + self.item_num * self.item_size
        try:
            self.shm = SharedMemory(name=self.shm_name, create=True, size=total_size)
        except PermissionError as e:
            raise PermissionError(
                "failed to create POSIX shared memory segment (requires /dev/shm access). "
                "If you're running in a restricted container/sandbox, ensure /dev/shm is writable "
                f"and try again (shm_name={self.shm_name})."
            ) from e
        except FileExistsError:
            if not force_recreate:
                raise
            try:
                old = SharedMemory(name=self.shm_name, create=False)
                old.close()
                old.unlink()
            except Exception:
                pass
            self.shm = SharedMemory(name=self.shm_name, create=True, size=total_size)

        # header
        self.shm.buf[:_HEADER_SIZE] = struct.pack(_HEADER_FMT, self.item_size, self.item_num)
        # init lengths to zero
        for i in range(self.item_num):
            off = _HEADER_SIZE + i * self.item_size
            self.shm.buf[off : off + _LEN_SIZE] = b"\x00\x00\x00\x00"

    def close(self) -> None:
        try:
            self.shm.close()
        except Exception:
            pass
        try:
            self.shm.unlink()
        except Exception:
            pass

    def max_payload_size(self) -> int:
        return self.item_size - _LEN_SIZE

    def add_seed(self, payload: bytes) -> Optional[int]:
        if payload is None:
            return None
        if not (0 < len(payload) <= self.max_payload_size()):
            return None
        if not self.unassigned:
            return -1
        idx = self.unassigned.pop()
        off = _HEADER_SIZE + idx * self.item_size
        self.shm.buf[off : off + _LEN_SIZE] = struct.pack(_LEN_FMT, len(payload))
        self.shm.buf[off + _LEN_SIZE : off + _LEN_SIZE + len(payload)] = payload
        return idx

    def release_seed(self, seed_id: int) -> None:
        if 0 <= seed_id < self.item_num:
            self.unassigned.add(seed_id)


@dataclass(frozen=True)
class SubmitBundle:
    script_id: int
    harness_name: str
    shm_name: str
    seed_ids: list[int]

    def serialize(self) -> bytes:
        return json.dumps(asdict(self)).encode("utf-8")

    @staticmethod
    def deserialize(raw: bytes) -> "SubmitBundle":
        obj = json.loads(raw.decode("utf-8", errors="replace"))
        return SubmitBundle(
            script_id=int(obj["script_id"]),
            harness_name=str(obj["harness_name"]),
            shm_name=str(obj["shm_name"]),
            seed_ids=[int(x) for x in obj["seed_ids"]],
        )


@dataclass
class _Inflight:
    ts: float
    seed_ids: list[int]
    inflight_path: Path
    original_path: Path


class ZmqSeedRouter:
    def __init__(
        self,
        *,
        bind_addr: str,
        harness_name: str,
        watch_dir: Path,
        shm_name: str,
        shm_items: int,
        shm_item_size: int,
        dealer_timeout_sec: int,
        ack_timeout_sec: int,
        poll_interval_sec: float,
        status_interval_sec: float,
        script_id: int,
        delete_processed: bool,
    ):
        self.bind_addr = bind_addr
        self.harness_name = harness_name
        self.watch_dir = watch_dir
        self.script_id = script_id
        self.delete_processed = delete_processed

        self.ctx = zmq.asyncio.Context.instance()
        self.sock = self.ctx.socket(zmq.ROUTER)
        try:
            self.sock.bind(self.bind_addr)
        except Exception:
            try:
                self.sock.close(linger=0)
            except Exception:
                pass
            raise

        try:
            self.producer = SeedShmemPoolProducer(
                shm_name=shm_name,
                item_num=shm_items,
                item_size=shm_item_size,
                force_recreate=True,
            )
        except Exception:
            try:
                self.sock.close(linger=0)
            except Exception:
                pass
            raise
        self.shm_name = shm_name

        self.dealer_timeout_sec = dealer_timeout_sec
        self.ack_timeout_sec = ack_timeout_sec
        self.poll_interval_sec = poll_interval_sec
        self.status_interval_sec = status_interval_sec

        self._dealers_last_seen: dict[bytes, float] = {}
        self._dealers_rr: list[bytes] = []
        self._rr_idx = 0
        self._inflight: dict[bytes, _Inflight] = {}
        self._ignored_dealers: set[bytes] = set()

        self._sent_total = 0
        self._ack_total = 0
        self._hb_total = 0
        self._scan_no_dealer_ticks = 0
        self._warned_no_dealer = False

    def _pick_dealer(self) -> Optional[bytes]:
        if not self._dealers_rr:
            return None
        self._rr_idx %= len(self._dealers_rr)
        dealer = self._dealers_rr[self._rr_idx]
        self._rr_idx = (self._rr_idx + 1) % len(self._dealers_rr)
        return dealer

    def _is_ignored_seed_file(self, p: Path) -> bool:
        name = p.name
        if name.startswith("."):
            return True
        for suf in (".tmp", ".sent", ".bad", ".inflight"):
            if name.endswith(suf):
                return True
        return False

    async def close(self) -> None:
        try:
            self.sock.close(linger=0)
        except Exception:
            pass
        try:
            self.producer.close()
        except Exception:
            pass

    def _hex(self, ident: bytes) -> str:
        try:
            return ident.hex()
        except Exception:
            return repr(ident)

    async def _send_seed_file(self, seed_path: Path) -> bool:
        dealer_id = self._pick_dealer()
        if dealer_id is None:
            return False

        try:
            payload = seed_path.read_bytes()
        except Exception:
            return False

        seed_id = self.producer.add_seed(payload)
        if seed_id is None:
            bad = seed_path.with_name(seed_path.name + ".bad")
            try:
                os.replace(seed_path, bad)
            except Exception:
                pass
            max_payload = self.producer.max_payload_size()
            reason = "empty" if len(payload) == 0 else f"too large (max_payload={max_payload})"
            logger.warning(
                "seed rejected (%s): %s -> %s (len=%s)",
                reason,
                seed_path,
                bad,
                len(payload),
            )
            return True

        if seed_id == -1:
            logger.debug("shm pool full; delaying send (seed=%s len=%s)", seed_path, len(payload))
            return False

        bundle = SubmitBundle(
            script_id=self.script_id,
            harness_name=self.harness_name,
            shm_name=self.shm_name,
            seed_ids=[seed_id],
        )
        msg_id = uuid.uuid4().hex.encode("utf-8")

        inflight_path = seed_path.with_name(seed_path.name + ".inflight")
        try:
            os.replace(seed_path, inflight_path)
        except Exception:
            self.producer.release_seed(seed_id)
            logger.warning("failed to mark inflight (seed=%s)", seed_path)
            return False

        try:
            await self.sock.send_multipart([dealer_id, b"SEED", msg_id, bundle.serialize()])
            self._inflight[msg_id] = _Inflight(
                ts=time.time(),
                seed_ids=[seed_id],
                inflight_path=inflight_path,
                original_path=seed_path,
            )
            self._sent_total += 1
            logger.info(
                "sent SEED dealer=%s msg_id=%s seed_id=%d file=%s bytes=%d",
                self._hex(dealer_id),
                msg_id.decode("utf-8", errors="replace"),
                seed_id,
                inflight_path.name,
                len(payload),
            )
            return True
        except Exception:
            self.producer.release_seed(seed_id)
            try:
                os.replace(inflight_path, seed_path)
            except Exception:
                pass
            logger.exception("failed to send SEED (dealer=%s seed=%s)", self._hex(dealer_id), seed_path)
            return False

    async def seed_scan_loop(self) -> None:
        while True:
            await asyncio.sleep(self.poll_interval_sec)
            if not self._dealers_rr:
                self._scan_no_dealer_ticks += 1
                continue
            try:
                files = [p for p in self.watch_dir.iterdir() if p.is_file() and not self._is_ignored_seed_file(p)]
            except FileNotFoundError:
                self.watch_dir.mkdir(parents=True, exist_ok=True)
                continue
            except Exception:
                continue

            # deterministic-ish to avoid starvation when many seeds exist
            files.sort(key=lambda p: (p.stat().st_mtime, p.name))
            for p in files:
                ok = await self._send_seed_file(p)
                if not ok:
                    break

    async def message_loop(self) -> None:
        while True:
            try:
                dealer_id, cmd, *frames = await self.sock.recv_multipart(flags=zmq.NOBLOCK)
            except zmq.Again:
                await asyncio.sleep(0.05)
                continue
            except Exception:
                await asyncio.sleep(0.1)
                continue

            now = time.time()
            if cmd == b"HEARTBEAT":
                self._hb_total += 1
                hb_harness = frames[0].decode("utf-8", errors="replace") if frames else ""
                if hb_harness and hb_harness != self.harness_name:
                    if dealer_id not in self._ignored_dealers:
                        self._ignored_dealers.add(dealer_id)
                        logger.warning(
                            "ignoring dealer with mismatched harness: dealer=%s harness=%s (expected %s)",
                            self._hex(dealer_id),
                            hb_harness,
                            self.harness_name,
                        )
                    continue

                first_seen = dealer_id not in self._dealers_last_seen
                self._dealers_last_seen[dealer_id] = now
                if dealer_id not in self._dealers_rr:
                    self._dealers_rr.append(dealer_id)
                if first_seen:
                    logger.info("dealer joined: dealer=%s harness=%s", self._hex(dealer_id), hb_harness or self.harness_name)
                continue

            if cmd == b"ACK" and len(frames) >= 2:
                msg_id = frames[0]
                bundle_raw = frames[1]
                try:
                    bundle = SubmitBundle.deserialize(bundle_raw)
                    for sid in bundle.seed_ids:
                        self.producer.release_seed(sid)
                except Exception:
                    pass

                info = self._inflight.pop(msg_id, None)
                if info is not None:
                    if self.delete_processed:
                        try:
                            info.inflight_path.unlink(missing_ok=True)
                        except Exception:
                            pass
                    else:
                        sent_path = info.original_path.with_name(info.original_path.name + ".sent")
                        try:
                            os.replace(info.inflight_path, sent_path)
                        except Exception:
                            pass
                self._ack_total += 1
                logger.info(
                    "recv ACK dealer=%s msg_id=%s inflight=%s",
                    self._hex(dealer_id),
                    msg_id.decode("utf-8", errors="replace"),
                    0 if info is None else 1,
                )
                continue

    async def cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            now = time.time()

            # Dealer timeout
            expired = [d for d, ts in self._dealers_last_seen.items() if now - ts > self.dealer_timeout_sec]
            for d in expired:
                self._dealers_last_seen.pop(d, None)
                try:
                    self._dealers_rr.remove(d)
                except ValueError:
                    pass
                logger.warning("dealer timed out: dealer=%s", self._hex(d))

            # Inflight ACK timeout -> release + retry
            for msg_id, info in list(self._inflight.items()):
                if now - info.ts <= self.ack_timeout_sec:
                    continue
                for sid in info.seed_ids:
                    self.producer.release_seed(sid)
                try:
                    os.replace(info.inflight_path, info.original_path)
                except Exception:
                    pass
                self._inflight.pop(msg_id, None)
                logger.warning("ACK timeout -> requeued: msg_id=%s file=%s", msg_id.decode("utf-8", errors="replace"), info.original_path.name)

    async def status_loop(self) -> None:
        if self.status_interval_sec <= 0:
            return
        while True:
            await asyncio.sleep(self.status_interval_sec)
            try:
                watch_files = 0
                sent_files = 0
                inflight_files = 0
                for p in self.watch_dir.iterdir():
                    if not p.is_file():
                        continue
                    if p.name.endswith(".sent"):
                        sent_files += 1
                    elif p.name.endswith(".inflight"):
                        inflight_files += 1
                    elif not self._is_ignored_seed_file(p):
                        watch_files += 1
                logger.info(
                    "status dealers=%d inflight=%d watch_files=%d inflight_files=%d sent_files=%d sent_total=%d ack_total=%d hb_total=%d",
                    len(self._dealers_rr),
                    len(self._inflight),
                    watch_files,
                    inflight_files,
                    sent_files,
                    self._sent_total,
                    self._ack_total,
                    self._hb_total,
                )
                if (not self._dealers_rr) and watch_files > 0 and not self._warned_no_dealer:
                    self._warned_no_dealer = True
                    logger.warning(
                        "no dealers connected, but %d seed files are pending in %s. "
                        "If you expect OOFMutate via ZMQ, verify the fuzzer sets "
                        "ATLJAZZER_ZMQ_ROUTER_ADDR + ATLJAZZER_ZMQ_HARNESS_ID and check ATLJAZZER_ZMQ_DEALER_LOG.",
                        watch_files,
                        self.watch_dir,
                    )
            except Exception:
                continue

    async def run(self) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            "router up: bind=%s watch_dir=%s shm=/dev/shm/%s max_payload=%dB",
            self.bind_addr,
            self.watch_dir,
            self.shm_name,
            self.producer.max_payload_size(),
        )
        try:
            await asyncio.gather(
                self.seed_scan_loop(),
                self.message_loop(),
                self.cleanup_loop(),
                self.status_loop(),
            )
        finally:
            await self.close()


def main() -> int:
    ap = argparse.ArgumentParser(
        "seed_router: ZMQ ROUTER that feeds atl-jazzer OOFMutate Dealer from a seed directory"
    )
    ap.add_argument("--bind", default=os.environ.get("ATLJAZZER_ZMQ_ROUTER_BIND", "tcp://127.0.0.1:5555"))
    ap.add_argument("--harness", required=True, help="Harness name (should match ATLJAZZER_ZMQ_HARNESS_ID)")
    watch_group = ap.add_mutually_exclusive_group(required=True)
    watch_group.add_argument("--watch-dir", help="Directory to watch for seed files")
    watch_group.add_argument("--work-dir", help="Work directory root (uses <work-dir>/zmq/seeds)")
    ap.add_argument("--shm-name", default=os.environ.get("ATLJAZZER_ZMQ_SHM_NAME", "atl-jazzer-shm"))
    ap.add_argument("--shm-items", type=int, default=int(os.environ.get("ATLJAZZER_ZMQ_SHM_ITEMS", "4096")))
    ap.add_argument("--shm-item-size", type=int, default=int(os.environ.get("ATLJAZZER_ZMQ_SHM_ITEM_SIZE", "8192")))
    ap.add_argument("--dealer-timeout", type=int, default=int(os.environ.get("ATLJAZZER_ZMQ_DEALER_TIMEOUT", "10")))
    ap.add_argument("--ack-timeout", type=int, default=int(os.environ.get("ATLJAZZER_ZMQ_ACK_TIMEOUT", "30")))
    ap.add_argument("--poll-interval", type=float, default=float(os.environ.get("ATLJAZZER_ZMQ_POLL_INTERVAL", "0.25")))
    ap.add_argument("--status-interval", type=float, default=float(os.environ.get("ATLJAZZER_ZMQ_STATUS_INTERVAL", "5.0")))
    ap.add_argument("--script-id", type=int, default=1)
    ap.add_argument("--delete-processed", action="store_true", help="Delete seeds after ACK instead of keeping *.sent")
    ap.add_argument("--log-level", default=os.environ.get("ATLJAZZER_ZMQ_LOG_LEVEL", "INFO"))
    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.watch_dir:
        watch_dir = Path(args.watch_dir).resolve()
    else:
        work_dir = Path(os.path.expanduser(args.work_dir)).resolve()
        watch_dir = work_dir / "zmq" / "seeds"

    router = ZmqSeedRouter(
        bind_addr=args.bind,
        harness_name=args.harness,
        watch_dir=watch_dir,
        shm_name=args.shm_name,
        shm_items=args.shm_items,
        shm_item_size=args.shm_item_size,
        dealer_timeout_sec=args.dealer_timeout,
        ack_timeout_sec=args.ack_timeout,
        poll_interval_sec=args.poll_interval,
        status_interval_sec=args.status_interval,
        script_id=args.script_id,
        delete_processed=bool(args.delete_processed),
    )

    try:
        asyncio.run(router.run())
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
