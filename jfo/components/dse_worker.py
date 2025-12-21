import os
import time
import shutil
import subprocess
import shlex
import signal
from pathlib import Path

from jfo.config import Config
from jfo.util.fs import ensure_dirs, claim_one_seed, import_generated, safe_list_files
from jfo.util.log import open_run_log


class DSEWorker:
    def __init__(self, cfg: Config, worker_id: int = 0):
        self.cfg = cfg
        self.worker_id = worker_id
        ensure_dirs(cfg.work_dir)
        self.corpus = cfg.corpus_dir_resolved
        self.mode = (cfg.mode or "default").lower()
        self.zmq_seed_dir = cfg.zmq_seeds_dir
        self.queue = cfg.queue_dir
        self.inflight = cfg.inflight_dir
        self.out_tmp_root = cfg.generated_dir
        self.logs = cfg.logs_dir
        self.engine = cfg.engine_path
        self.inflight.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        self.corpus.mkdir(parents=True, exist_ok=True)

    def run(self):
        wid = self.worker_id
        print(f"[DSE-{wid}] backend={self.cfg.dse_backend} engine={self.engine} mode={self.mode}")
        while True:
            seed_claimed = claim_one_seed(self.queue, self.inflight, self.worker_id)
            if seed_claimed is None:
                time.sleep(self.cfg.dse_poll_interval)
                continue

            out_tmp = self.out_tmp_root / f"w{wid}"
            shutil.rmtree(out_tmp, ignore_errors=True)
            out_tmp.mkdir(parents=True, exist_ok=True)

            log_path = self.logs / f"dse_w{wid}_{seed_claimed.name}.log"
            cmd = [os.environ.get("PYTHON", "python3"), str(self.engine)]
            if (self.cfg.dse_backend or "").lower() in {"spf", "gdart"}:
                if self.cfg.fuzzer_path is None:
                    raise SystemExit(
                        "[dse] missing fuzzer path in config (pass --fuzzer-path via CLI; required for spf/gdart)"
                    )
                cmd += ["--fuzzer-path", str(self.cfg.fuzzer_path), "--work-dir", str(self.cfg.work_dir)]
            cmd += [str(seed_claimed), str(out_tmp)]
            cmd_str = shlex.join(cmd)
            print(f"[DSE-{wid}] running:", cmd_str)

            start = time.time()
            imported_n = None
            imported_stats = None
            zmq_n = None
            zmq_stats = None
            run_log = open_run_log(log_path, logger_name=f"dse_w{wid}")
            try:
                logger = run_log.logger
                lf = run_log.stream
                logger.info("worker=%s pid=%s backend=%s engine=%s", wid, os.getpid(), self.cfg.dse_backend, self.engine)
                logger.info("seed=%s", seed_claimed)
                logger.info("out_tmp=%s", out_tmp)
                logger.info("corpus=%s", self.corpus)
                logger.info("mode=%s", self.mode)
                if self.mode == "atl":
                    logger.info("zmq_seed_dir=%s", self.zmq_seed_dir)
                logger.info(
                    "queue_files=%s inflight_files=%s",
                    len(safe_list_files(self.queue)),
                    len(safe_list_files(self.inflight)),
                )
                logger.info("timeout_sec=%s", self.cfg.dse_timeout_sec)
                logger.info("cmd=%s", cmd_str)

                p = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
                logger.info("engine_pid=%s", p.pid)
                try:
                    p.wait(timeout=self.cfg.dse_timeout_sec)
                    rc = p.returncode
                    timed_out = False
                except subprocess.TimeoutExpired:
                    timed_out = True
                    logger.info("timeout after %ss; killing engine_pid=%s", self.cfg.dse_timeout_sec, p.pid)
                    # Ensure child processes (e.g., JVM) are also terminated.
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except Exception:
                        p.kill()
                    p.wait()
                    rc = p.returncode if p.returncode is not None else -1

                dur = time.time() - start
                logger.info("engine_rc=%s duration_sec=%.3f timed_out=%s", rc, dur, int(timed_out))

                produced = safe_list_files(out_tmp)
                produced_bytes = sum(pth.stat().st_size for pth in produced)
                logger.info("out_tmp_files=%s out_tmp_bytes=%s", len(produced), produced_bytes)
                spf_logs_dir = out_tmp / "spf_logs"
                if spf_logs_dir.is_dir():
                    logger.info("spf_logs_dir=%s spf_log_files=%s", spf_logs_dir, len(safe_list_files(spf_logs_dir)))

                if rc == 0:
                    if self.mode != "atl":
                        imported_n, imported_stats = import_generated(
                            out_tmp,
                            self.corpus,
                            self.cfg.min_generated_bytes,
                            self.cfg.max_generated_bytes_corpus,
                            self.cfg.max_import_per_seed,
                            return_stats=True,
                        )
                        logger.info(
                            "deliver_to_corpus: scanned=%s eligible=%s imported=%s skipped_small=%s skipped_large=%s "
                            "skipped_dup_batch=%s skipped_dup_corpus=%s skipped_dst_exists=%s errors=%s",
                            imported_stats.scanned,
                            imported_stats.eligible,
                            imported_stats.imported,
                            imported_stats.skipped_too_small,
                            imported_stats.skipped_too_large,
                            imported_stats.skipped_dup_batch,
                            imported_stats.skipped_dup_corpus,
                            imported_stats.skipped_dst_exists,
                            imported_stats.errors,
                        )

                    if self.mode == "atl":
                        self.zmq_seed_dir.mkdir(parents=True, exist_ok=True)
                        zmq_max = min(self.cfg.max_generated_bytes_zmq, self.cfg.zmq_max_payload_bytes)
                        zmq_n, zmq_stats = import_generated(
                            out_tmp,
                            self.zmq_seed_dir,
                            self.cfg.min_generated_bytes,
                            zmq_max,
                            self.cfg.max_import_per_seed,
                            return_stats=True,
                        )
                        logger.info(
                            "deliver_to_zmq_seed_dir: scanned=%s eligible=%s imported=%s skipped_small=%s skipped_large=%s "
                            "skipped_dup_batch=%s skipped_dup_dir=%s skipped_dst_exists=%s errors=%s",
                            zmq_stats.scanned,
                            zmq_stats.eligible,
                            zmq_stats.imported,
                            zmq_stats.skipped_too_small,
                            zmq_stats.skipped_too_large,
                            zmq_stats.skipped_dup_batch,
                            zmq_stats.skipped_dup_corpus,
                            zmq_stats.skipped_dst_exists,
                            zmq_stats.errors,
                        )
            finally:
                run_log.close()

            if rc != 0:
                print(f"[DSE-{wid}] failed rc={rc} seed={seed_claimed.name}")
            else:
                parts = []
                if imported_n is not None:
                    parts.append(f"corpus={imported_n}")
                if zmq_n is not None:
                    parts.append(f"zmq={zmq_n}")
                msg = " ".join(parts) if parts else "no-op"
                print(f"[DSE-{wid}] delivered {msg}")

            try:
                seed_claimed.unlink()
            except FileNotFoundError:
                pass


def dse_worker(cfg: Config, worker_id: int = 0):
    DSEWorker(cfg, worker_id).run()
