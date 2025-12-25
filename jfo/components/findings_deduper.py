import base64
from collections import deque
import hashlib
import json
import os
import re
import shutil
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from jfo.config import Config


_RE_DEDUP_TOKEN = re.compile(r"\bDEDUP_TOKEN:\s*([0-9a-fA-F]{16})\b")
_RE_BASE64 = re.compile(r"^\s*Base64:\s*([A-Za-z0-9+/=]+)\s*$")
_RE_TEST_UNIT = re.compile(r"\bTest unit written to\s+(\S+)\s*$")
_RE_ARTIFACT_SHA1 = re.compile(r"(?:^|/)(?:crash|timeout|oom|leak)-([0-9a-fA-F]{40})(?:\s|$)")
_RE_JAVA_EXCEPTION = re.compile(r"^\s*==\s*Java Exception:\s*(.*)\s*$")
_RE_STACK_LINE = re.compile(r"^\s*(?:at\s+|\tat\s+).+")
_RE_CAUSED_BY = re.compile(r"^\s*Caused by:\s+.*")
_RE_STACK_FILE_LINE = re.compile(r"\b([A-Za-z0-9_$]+\.java):(\d+)\b")


@dataclass(frozen=True, slots=True)
class CrashInfo:
    exception: str | None  # exception class name
    msg: str | None  # full "Class: message" string from Jazzer
    stacktrace: list[str]
    artifact_path: str | None
    artifact_kind: str | None
    base64: str | None


@dataclass(frozen=True, slots=True)
class Finding:
    ts: float
    time: str
    token: str
    sha1: str
    source_log: str
    source_line: int | None
    crash: CrashInfo | None
    excerpt_log: str | None


def _safe_mkdir(p: Path) -> None:
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _link_or_copy(src: Path, dst: Path) -> None:
    if dst.exists():
        return
    _safe_mkdir(dst.parent)
    try:
        os.link(src, dst)
        return
    except Exception:
        pass
    shutil.copy2(src, dst)


def _compute_sha1_from_base64(b64: str) -> str | None:
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception:
        return None
    return hashlib.sha1(raw).hexdigest()


def _extract_crash_info(lines: list[str]) -> CrashInfo:
    msg: str | None = None
    exc: str | None = None
    stack: list[str] = []
    artifact_path: str | None = None
    artifact_kind: str | None = None
    b64: str | None = None

    for line in lines:
        if msg is None:
            m = _RE_JAVA_EXCEPTION.match(line)
            if m:
                msg = m.group(1).strip() or None
                if msg:
                    # Typical form: "java.lang.IllegalArgumentException: message..."
                    head = msg.split(":", 1)[0].strip()
                    exc = head or None
        if _RE_STACK_LINE.match(line) or _RE_CAUSED_BY.match(line):
            stack.append(line.rstrip())
        m_tu = _RE_TEST_UNIT.search(line)
        if m_tu:
            artifact_path = m_tu.group(1)
            m_kind = re.search(r"(?:^|/)(crash|timeout|oom|leak)-[0-9a-fA-F]{40}", artifact_path)
            if m_kind:
                artifact_kind = m_kind.group(1).lower()
        m_b64 = _RE_BASE64.match(line)
        if m_b64:
            b64 = m_b64.group(1)

    return CrashInfo(
        exception=exc,
        msg=msg,
        stacktrace=stack,
        artifact_path=artifact_path,
        artifact_kind=artifact_kind,
        base64=b64,
    )


def _ts_iso(ts: float | None = None) -> str:
    if ts is None:
        ts = time.time()
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return ""


def _parse_ts_iso(s: str | None) -> float | None:
    if not s:
        return None
    try:
        ss = s.strip()
        if ss.endswith("Z"):
            ss = ss[:-1] + "+00:00"
        return datetime.fromisoformat(ss).timestamp()
    except Exception:
        return None


def _extract_top_file_line(stacktrace: list[str] | None) -> tuple[str | None, int | None]:
    if not stacktrace:
        return (None, None)
    for line in stacktrace:
        if not isinstance(line, str):
            continue
        m = None
        for m in _RE_STACK_FILE_LINE.finditer(line):
            pass
        if not m:
            continue
        fname = m.group(1)
        try:
            lno = int(m.group(2))
        except Exception:
            continue
        return (fname, lno)
    return (None, None)


def _extract_top_file_lines(stacktrace: list[str] | None, *, n: int = 3) -> list[tuple[str, int]]:
    if not stacktrace or n <= 0:
        return []
    out: list[tuple[str, int]] = []
    for line in stacktrace:
        if not isinstance(line, str):
            continue
        m = None
        for m in _RE_STACK_FILE_LINE.finditer(line):
            pass
        if not m:
            continue
        fname = m.group(1)
        try:
            lno = int(m.group(2))
        except Exception:
            continue
        out.append((fname, lno))
        if len(out) >= n:
            break
    return out


class _TailState:
    def __init__(self) -> None:
        self.offset = 0
        self.buf = ""
        self.line_no = 0
        self.cur_token: str | None = None
        self.cur_token_ts = 0.0
        self.cur_sha1: str | None = None
        self.cur_sha1_ts = 0.0
        self.cur_source_line_no: int | None = None
        self.recent_lines: deque[str] = deque(maxlen=1500)

    def reset_current(self) -> None:
        self.cur_token = None
        self.cur_token_ts = 0.0
        self.cur_sha1 = None
        self.cur_sha1_ts = 0.0
        self.cur_source_line_no = None


def _iter_target_logs(logs_dir: Path) -> list[Path]:
    out: list[Path] = []
    for name in ("fuzzer.log",):
        p = logs_dir / name
        if p.is_file():
            out.append(p)
    for p in logs_dir.glob("fuzz-*.log"):
        if p.is_file():
            out.append(p)
    # stable-ish order
    out.sort(key=lambda p: p.name)
    return out


def _token_dir(cfg: Config, token: str) -> Path:
    return cfg.findings_dir / token.lower()

def _crash_dir(cfg: Config, *, token: str, sha1: str) -> Path:
    return _token_dir(cfg, token) / sha1.lower()


def _reproducer_sources(cfg: Config, sha1: str) -> list[Path]:
    return [
        cfg.reproducers_dir / f"Crash_{sha1}.java",
        cfg.reproducers_dir / f"Crash-{sha1}.java",
    ]


def _extract_excerpt(st: _TailState) -> list[str]:
    """
    Best-effort crash excerpt from the recent log tail.
    """
    lines = list(st.recent_lines)
    if not lines:
        return []
    end = len(lines)
    start = max(0, end - 400)

    # Try to start at the most recent "== Java Exception:" marker.
    for i in range(end - 1, -1, -1):
        if _RE_JAVA_EXCEPTION.match(lines[i]):
            start = i
            break

    # Keep the excerpt bounded even if the exception is very old.
    if end - start > 800:
        start = end - 800

    excerpt = lines[start:end]

    # Try to end at the last "Test unit written to ..." or "Base64:" line.
    last_signal = -1
    for i, line in enumerate(excerpt):
        if _RE_TEST_UNIT.search(line) or _RE_BASE64.match(line):
            last_signal = i
    if last_signal != -1:
        excerpt = excerpt[: last_signal + 1]

    # Strip libFuzzer noise (e.g. MS/hexdump) while keeping the crash essence.
    kept: list[str] = []
    for line in excerpt:
        if _RE_JAVA_EXCEPTION.match(line):
            kept.append(line.rstrip())
            continue
        if _RE_STACK_LINE.match(line) or _RE_CAUSED_BY.match(line):
            kept.append(line.rstrip())
            continue
        if _RE_DEDUP_TOKEN.search(line):
            kept.append(line.rstrip())
            continue
        if line.strip() == "== libFuzzer crashing input ==":
            kept.append(line.rstrip())
            continue
        if _RE_TEST_UNIT.search(line) or _RE_BASE64.match(line):
            kept.append(line.rstrip())
            continue

    return kept


def _maybe_emit_current(
    cfg: Config,
    *,
    st: _TailState,
    source_log: Path,
    source_line_no: int | None,
    seen_pairs: set[tuple[str, str]],
) -> None:
    if not st.cur_token or not st.cur_sha1:
        return
    key = (st.cur_token.lower(), st.cur_sha1.lower())
    if key in seen_pairs:
        st.reset_current()
        return
    seen_pairs.add(key)
    excerpt_lines = _extract_excerpt(st)
    _handle_finding(
        cfg,
        token=st.cur_token,
        sha1=st.cur_sha1,
        source_log=source_log,
        source_line_no=source_line_no if source_line_no is not None else st.cur_source_line_no,
        excerpt_lines=excerpt_lines,
    )
    st.reset_current()


def _extract_sha1_from_test_unit(line: str) -> str | None:
    m_tu = _RE_TEST_UNIT.search(line)
    if not m_tu:
        return None
    m_sha1 = _RE_ARTIFACT_SHA1.search(m_tu.group(1))
    if not m_sha1:
        return None
    return m_sha1.group(1).lower()


def _process_line(
    cfg: Config, *, st: _TailState, line: str, line_no: int, source_log: Path, seen_pairs: set[tuple[str, str]]
) -> None:
    now = time.time()

    # A new Java exception marks the start of the next crash block. Flush the previous
    # crash before appending this line so the excerpt doesn't "jump" to the new exception.
    if _RE_JAVA_EXCEPTION.match(line):
        if st.cur_token and st.cur_sha1:
            _maybe_emit_current(
                cfg,
                st=st,
                source_log=source_log,
                source_line_no=st.cur_source_line_no,
                seen_pairs=seen_pairs,
            )

    st.recent_lines.append(line)

    # Track the current crash token.
    m = _RE_DEDUP_TOKEN.search(line)
    if m:
        token = m.group(1).lower()
        # De-dupe duplicate token lines printed to multiple streams.
        if st.cur_token == token and (now - st.cur_token_ts) < 1.0:
            pass
        else:
            # If we somehow see a new token while still holding a completed crash, emit first.
            if st.cur_token and st.cur_sha1 and st.cur_token != token:
                _maybe_emit_current(
                    cfg,
                    st=st,
                    source_log=source_log,
                    source_line_no=st.cur_source_line_no,
                    seen_pairs=seen_pairs,
                )
            st.cur_token = token
            st.cur_token_ts = now
            st.cur_source_line_no = line_no
            st.cur_sha1 = None
            st.cur_sha1_ts = 0.0

    # Prefer SHA-1 from the artifact path (it also lets excerpts capture "Test unit written...").
    sha1_tu = _extract_sha1_from_test_unit(line)
    if sha1_tu and st.cur_token:
        st.cur_sha1 = sha1_tu
        st.cur_sha1_ts = now
        st.cur_source_line_no = line_no

    # Use Base64 only as a fallback to derive the SHA-1 when no artifact line exists.
    m_b64 = _RE_BASE64.match(line)
    if m_b64 and st.cur_token:
        st.cur_source_line_no = line_no
        if not st.cur_sha1:
            sha1_b64 = _compute_sha1_from_base64(m_b64.group(1))
            if sha1_b64:
                st.cur_sha1 = sha1_b64.lower()
                st.cur_sha1_ts = now
        if st.cur_sha1:
            _maybe_emit_current(cfg, st=st, source_log=source_log, source_line_no=line_no, seen_pairs=seen_pairs)

    # If we have a token+sha1 but never see Base64, flush after a short idle period.
    if st.cur_token and st.cur_sha1 and (now - st.cur_sha1_ts) > 5.0:
        _maybe_emit_current(
            cfg,
            st=st,
            source_log=source_log,
            source_line_no=st.cur_source_line_no,
            seen_pairs=seen_pairs,
        )


def rebuild_findings_once(cfg: Config) -> None:
    """
    One-shot rebuild of <work-dir>/findings by scanning existing logs.

    This does not rerun the fuzzer; it only parses <work-dir>/logs.
    """
    logs_dir = cfg.logs_dir
    _safe_mkdir(logs_dir)
    _safe_mkdir(cfg.reproducers_dir)
    _safe_mkdir(cfg.findings_dir)

    seen_pairs: set[tuple[str, str]] = set()
    for path in _iter_target_logs(logs_dir):
        st = _TailState()
        try:
            for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                _process_line(cfg, st=st, line=raw, line_no=i, source_log=path, seen_pairs=seen_pairs)
        except Exception:
            continue
        # Flush any trailing crash at EOF.
        _maybe_emit_current(
            cfg,
            st=st,
            source_log=path,
            source_line_no=st.cur_source_line_no,
            seen_pairs=seen_pairs,
        )
    _write_overview(cfg, force=True)


def _handle_finding(
    cfg: Config,
    *,
    token: str,
    sha1: str,
    source_log: Path,
    source_line_no: int | None,
    excerpt_lines: list[str],
) -> None:
    _safe_mkdir(cfg.findings_dir)
    index_path = cfg.findings_dir / "index.json"
    state_path = cfg.findings_dir / "state.json"

    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        state = {}
    token_map: dict[str, str] = dict(state.get("token_primary_sha1", {}) or {})
    sha1_map: dict[str, str] = dict(state.get("sha1_token", {}) or {})

    token_l = token.lower()
    sha1 = sha1.lower()
    primary = token_map.get(token_l)
    is_primary = primary is None
    if is_primary:
        token_map[token_l] = sha1
        primary = sha1
    sha1_map[sha1] = token_l

    # Always keep a stable directory per unique crash: <token>/<sha1>/.
    dest_dir = _crash_dir(cfg, token=token_l, sha1=sha1)
    _safe_mkdir(dest_dir)
    meta_path = dest_dir / "finding.json"
    meta_exists = meta_path.exists()

    excerpt_name = "finding.log"
    excerpt_path = dest_dir / excerpt_name
    try:
        excerpt_path.write_text("\n".join(excerpt_lines).rstrip() + "\n", encoding="utf-8", errors="replace")
    except Exception:
        pass

    # Copy/link the Java reproducer if present.
    for repro_src in _reproducer_sources(cfg, sha1):
        if repro_src.is_file():
            _link_or_copy(repro_src, dest_dir / repro_src.name)

    crash_info = _extract_crash_info(excerpt_lines) if excerpt_lines else None

    # Prefer the artifact file mtime as the crash timestamp (more meaningful than "when the deduper noticed it").
    artifact_file: Path | None = None
    artifact_ts: float | None = None
    candidates: list[Path] = []
    if crash_info and crash_info.artifact_path:
        candidates.append(Path(crash_info.artifact_path))
    for prefix in ("crash", "timeout", "oom", "leak"):
        candidates.append(cfg.artifacts_dir / f"{prefix}-{sha1}")

    for cand in candidates:
        try:
            # The log line may arrive slightly before the artifact file is flushed to disk.
            deadline = time.time() + 1.0
            while time.time() < deadline:
                if cand.is_file():
                    artifact_file = cand
                    artifact_ts = cand.stat().st_mtime
                    break
                time.sleep(0.05)
            if artifact_file is not None:
                break
        except Exception:
            continue

    # Copy/link the artifact file if present.
    if artifact_file is not None and artifact_file.is_file():
        try:
            _link_or_copy(artifact_file, dest_dir / artifact_file.name)
        except Exception:
            pass

    ts = float(artifact_ts) if artifact_ts is not None else time.time()
    finding = Finding(
        ts=ts,
        time=_ts_iso(ts),
        token=token_l,
        sha1=sha1,
        source_log=str(source_log),
        source_line=source_line_no,
        crash=crash_info,
        excerpt_log=excerpt_name,
    )

    # Keep index.json minimal (easy to scan, no large blob fields).
    idx_entry = asdict(finding)
    idx_entry.pop("excerpt_log", None)
    if isinstance(idx_entry.get("crash"), dict):
        # Keep index.json minimal; omit derived exception class.
        idx_entry["crash"].pop("exception", None)
    try:
        if not meta_exists:
            meta = asdict(finding)
            meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            # If an old record exists, fill in crash/excerpt fields opportunistically.
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            # Keep the earliest known crash time (stable even if the process restarts).
            try:
                prev_ts = meta.get("ts")
                if isinstance(prev_ts, (int, float)):
                    meta["ts"] = float(min(float(prev_ts), float(finding.ts)))
                else:
                    meta["ts"] = float(finding.ts)
            except Exception:
                meta["ts"] = float(finding.ts)
            if meta.get("time") is None:
                meta["time"] = _ts_iso(meta.get("ts"))
            if meta.get("excerpt_log") is None:
                meta["excerpt_log"] = excerpt_name
            if meta.get("source_line") is None:
                meta["source_line"] = source_line_no
            if meta.get("crash") is None and crash_info is not None:
                meta["crash"] = asdict(crash_info)
            meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    try:
        if not meta_exists:
            try:
                idx = json.loads(index_path.read_text(encoding="utf-8"))
                if not isinstance(idx, list):
                    idx = []
            except Exception:
                idx = []
            idx.append(idx_entry)
            index_path.write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

    try:
        state_path.write_text(
            json.dumps(
                {"token_primary_sha1": token_map, "sha1_token": sha1_map},
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass

    try:
        _write_overview(cfg)
    except Exception:
        pass


_OVERVIEW_THROTTLE_SEC = 2.0
_last_overview_write = 0.0


def _write_overview(cfg: Config, *, force: bool = False) -> None:
    global _last_overview_write
    now = time.time()
    if (not force) and (now - _last_overview_write) < _OVERVIEW_THROTTLE_SEC:
        return
    _last_overview_write = now

    state_path = cfg.findings_dir / "state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        state = {}
    token_primary: dict[str, str] = dict(state.get("token_primary_sha1", {}) or {})
    sha1_token: dict[str, str] = dict(state.get("sha1_token", {}) or {})

    def _rel(p: Path) -> str:
        try:
            return str(p.resolve().relative_to(cfg.work_dir.resolve()))
        except Exception:
            return str(p)

    token_summaries: list[dict] = []

    # Dedup-token summaries (primary crash only).
    for token, primary_sha1 in sorted(token_primary.items()):
        meta_path = _crash_dir(cfg, token=token, sha1=primary_sha1) / "finding.json"
        msg: str | None = None
        exc: str | None = None
        kind = None
        top_file: str | None = None
        top_line: int | None = None
        top2_file: str | None = None
        top2_line: int | None = None
        top3_file: str | None = None
        top3_line: int | None = None
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            crash = meta.get("crash") or {}
            msg = crash.get("msg")
            exc = crash.get("exception")
            kind = crash.get("artifact_kind")
            st = crash.get("stacktrace") if isinstance(crash, dict) else None
            if isinstance(st, list):
                frames = _extract_top_file_lines(st, n=3)
                if len(frames) >= 1:
                    top_file, top_line = frames[0]
                if len(frames) >= 2:
                    top2_file, top2_line = frames[1]
                if len(frames) >= 3:
                    top3_file, top3_line = frames[2]
        except Exception:
            pass
        uniq_sha1s = [s for s, t in sha1_token.items() if t == token]
        uniq = len(uniq_sha1s)
        inputs: list[dict] = []
        first_ts: float | None = None
        for s in uniq_sha1s:
            crash_dir = _crash_dir(cfg, token=token, sha1=s)
            entry: dict = {"path": f"{token}/{s}"}
            try:
                fmeta = json.loads((crash_dir / "finding.json").read_text(encoding="utf-8"))
                ts = fmeta.get("ts")
                if isinstance(ts, (int, float)):
                    first_ts = ts if first_ts is None else min(first_ts, float(ts))
                elif isinstance(fmeta.get("time"), str):
                    pts = _parse_ts_iso(fmeta.get("time"))
                    if pts is not None:
                        first_ts = pts if first_ts is None else min(first_ts, float(pts))
            except Exception:
                pass
            for prefix in ("crash", "timeout", "oom", "leak"):
                cand = cfg.artifacts_dir / f"{prefix}-{s}"
                if cand.is_file():
                    entry["artifact_file"] = _rel(cand)
                    break
            for repro_src in _reproducer_sources(cfg, s):
                if repro_src.is_file():
                    entry["reproducer_file"] = _rel(repro_src)
                    break
            inputs.append(entry)

        token_summaries.append(
            {
                "token": token,
                "first_time": _ts_iso(first_ts) if first_ts is not None else None,
                "exception": exc,
                "msg": msg,
                "top_file": top_file,
                "top_line": top_line,
                "top2_file": top2_file,
                "top2_line": top2_line,
                "top3_file": top3_file,
                "top3_line": top3_line,
                "artifact_kind": kind,
                "unique_inputs": uniq,
                # Keep only one path-like field per input; don't duplicate with dir+path.
                "inputs": sorted(
                    [
                        {
                            "path": i.get("path"),
                            "artifact_file": i.get("artifact_file"),
                            "reproducer_file": i.get("reproducer_file"),
                        }
                        for i in inputs
                    ],
                    key=lambda d: str(d.get("path", "")),
                ),
                "_first_ts": first_ts,
            }
        )

    # Sort by (exception class, top frame file:line) for easy visual grouping.
    token_summaries.sort(
        key=lambda t: (
            str(t.get("exception") or ""),
            str(t.get("top_file") or ""),
            int(t.get("top_line") or 0),
            str(t.get("token") or ""),
        )
    )
    for t in token_summaries:
        t.pop("_first_ts", None)

    overview = {
        "time": _ts_iso(now),
        "tokens": token_summaries,
    }
    (cfg.findings_dir / "overview.json").write_text(
        json.dumps(overview, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )

    # Also write a quick human-readable overview.
    lines: list[str] = []
    lines.append(f"# Findings Overview ({cfg.work_dir.name})")
    lines.append(f"- Generated: {overview['time']}")
    lines.append(f"- Tokens: {len(token_summaries)}")
    lines.append("")
    lines.append("## Tokens")
    lines.append("| token | first_time | unique_inputs | exception | top | kind |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for t in token_summaries:
        token = (t.get("token") or "?").replace("|", "\\|")
        uniq = int(t.get("unique_inputs", 0) or 0)
        first_time = (t.get("first_time") or "").replace("|", "\\|")
        exc_cls = (t.get("exception") or "").replace("|", "\\|")
        tf = (t.get("top_file") or "").replace("|", "\\|")
        tl = t.get("top_line")
        top = f"{tf}:{int(tl)}" if (tf and isinstance(tl, int)) else tf
        kind = (t.get("artifact_kind") or "?").replace("|", "\\|")
        lines.append(f"| `{token}` | `{first_time}` | {uniq} | {exc_cls} | `{top}` | {kind} |")
    (cfg.findings_dir / "overview.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_findings_deduper(cfg: Config) -> None:
    """
    Watches <work-dir>/logs for Jazzer findings and groups them by DEDUP_TOKEN.

    For each finding it tries to derive the input SHA-1 either from:
      - `Test unit written to .../<kind>-<sha1>` output (preferred), or
      - `Base64: ...` output (fallback; only when no artifact line exists).

    Reproducers and artifacts are hardlinked (or copied) into:
      <work-dir>/findings/<dedup_token>/<sha1>/
    """
    logs_dir = cfg.logs_dir
    _safe_mkdir(logs_dir)
    _safe_mkdir(cfg.reproducers_dir)
    _safe_mkdir(cfg.findings_dir)

    states: dict[Path, _TailState] = {}
    # Avoid repeated processing within a single run (e.g. DEDUP_TOKEN printed twice).
    seen_pairs: set[tuple[str, str]] = set()

    while True:
        for p in _iter_target_logs(logs_dir):
            states.setdefault(p, _TailState())

        for path, st in list(states.items()):
            if not path.exists():
                continue
            try:
                size = path.stat().st_size
            except Exception:
                continue
            if st.offset > size:
                st.offset = 0
                st.buf = ""
                st.line_no = 0
                st.reset_current()
                st.recent_lines.clear()
            try:
                with path.open("rb") as f:
                    f.seek(st.offset)
                    chunk = f.read()
                    st.offset = f.tell()
            except Exception:
                continue
            if not chunk:
                continue
            text = chunk.decode("utf-8", errors="replace")
            st.buf += text
            lines = st.buf.split("\n")
            st.buf = lines[-1]
            for line in lines[:-1]:
                st.line_no += 1
                _process_line(cfg, st=st, line=line, line_no=st.line_no, source_log=path, seen_pairs=seen_pairs)

        time.sleep(0.25)
