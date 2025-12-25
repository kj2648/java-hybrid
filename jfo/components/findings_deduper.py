import base64
from collections import deque
import hashlib
import json
import os
import re
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from jfo.config import Config


_RE_DEDUP_TOKEN = re.compile(r"\bDEDUP_TOKEN:\s*([0-9a-fA-F]{16})\b")
_RE_BASE64 = re.compile(r"^\s*Base64:\s*([A-Za-z0-9+/=]+)\s*$")
_RE_TEST_UNIT = re.compile(r"\bTest unit written to\s+(\S+)\s*$")
_RE_ARTIFACT_SHA1 = re.compile(r"(?:^|/)(?:crash|timeout|oom|leak)-([0-9a-fA-F]{40})(?:\s|$)")
_RE_ARTIFACT_NAME = re.compile(r"^(?:crash|timeout|oom|leak)-([0-9a-fA-F]{40})$")
_RE_JAVA_EXCEPTION = re.compile(r"^\s*==\s*Java Exception:\s*(.*)\s*$")
_RE_STACK_LINE = re.compile(r"^\s*(?:at\s+|\tat\s+).+")
_RE_CAUSED_BY = re.compile(r"^\s*Caused by:\s+.*")


@dataclass(frozen=True, slots=True)
class CrashInfo:
    exception: str | None
    stacktrace: list[str]
    artifact_path: str | None
    artifact_kind: str | None
    base64: str | None


@dataclass(frozen=True, slots=True)
class Finding:
    ts: float
    token: str
    sha1: str
    source_log: str
    source_line: str
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
    exc: str | None = None
    stack: list[str] = []
    artifact_path: str | None = None
    artifact_kind: str | None = None
    b64: str | None = None

    for line in lines:
        if exc is None:
            m = _RE_JAVA_EXCEPTION.match(line)
            if m:
                exc = m.group(1).strip() or None
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
        stacktrace=stack,
        artifact_path=artifact_path,
        artifact_kind=artifact_kind,
        base64=b64,
    )


class _TailState:
    def __init__(self) -> None:
        self.offset = 0
        self.buf = ""
        self.cur_token: str | None = None
        self.cur_token_ts = 0.0
        self.cur_sha1: str | None = None
        self.cur_sha1_ts = 0.0
        self.cur_seen_base64 = False
        self.cur_source_line = ""
        self.recent_lines: deque[str] = deque(maxlen=1500)

    def reset_current(self) -> None:
        self.cur_token = None
        self.cur_token_ts = 0.0
        self.cur_sha1 = None
        self.cur_sha1_ts = 0.0
        self.cur_seen_base64 = False
        self.cur_source_line = ""


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


def _maybe_emit_current(cfg: Config, *, st: _TailState, source_log: Path, source_line: str, seen_pairs: set[tuple[str, str]]) -> None:
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
        source_line=(source_line or st.cur_source_line or "").strip(),
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
    cfg: Config, *, st: _TailState, line: str, source_log: Path, seen_pairs: set[tuple[str, str]]
) -> None:
    now = time.time()

    # A new Java exception marks the start of the next crash block. Flush the previous
    # crash before appending this line so the excerpt doesn't "jump" to the new exception.
    if _RE_JAVA_EXCEPTION.match(line):
        if st.cur_token and st.cur_sha1:
            _maybe_emit_current(cfg, st=st, source_log=source_log, source_line=st.cur_source_line, seen_pairs=seen_pairs)

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
                _maybe_emit_current(cfg, st=st, source_log=source_log, source_line=st.cur_source_line, seen_pairs=seen_pairs)
            st.cur_token = token
            st.cur_token_ts = now
            st.cur_source_line = line
            st.cur_seen_base64 = False
            st.cur_sha1 = None
            st.cur_sha1_ts = 0.0

    # Prefer SHA-1 from the artifact path (it also lets excerpts capture "Test unit written...").
    sha1_tu = _extract_sha1_from_test_unit(line)
    if sha1_tu and st.cur_token:
        st.cur_sha1 = sha1_tu
        st.cur_sha1_ts = now
        st.cur_source_line = line

    # Use Base64 only as a fallback to derive the SHA-1 when no artifact line exists.
    m_b64 = _RE_BASE64.match(line)
    if m_b64 and st.cur_token:
        st.cur_seen_base64 = True
        st.cur_source_line = line
        if not st.cur_sha1:
            sha1_b64 = _compute_sha1_from_base64(m_b64.group(1))
            if sha1_b64:
                st.cur_sha1 = sha1_b64.lower()
                st.cur_sha1_ts = now
        if st.cur_sha1:
            _maybe_emit_current(cfg, st=st, source_log=source_log, source_line=line, seen_pairs=seen_pairs)

    # If we have a token+sha1 but never see Base64, flush after a short idle period.
    if st.cur_token and st.cur_sha1 and (now - st.cur_sha1_ts) > 5.0:
        _maybe_emit_current(cfg, st=st, source_log=source_log, source_line=st.cur_source_line, seen_pairs=seen_pairs)


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
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                _process_line(cfg, st=st, line=raw, source_log=path, seen_pairs=seen_pairs)
        except Exception:
            continue
        # Flush any trailing crash at EOF.
        _maybe_emit_current(cfg, st=st, source_log=path, source_line=st.cur_source_line, seen_pairs=seen_pairs)


def _handle_finding(
    cfg: Config, *, token: str, sha1: str, source_log: Path, source_line: str, excerpt_lines: list[str]
) -> None:
    _safe_mkdir(cfg.findings_dir)
    index_path = cfg.findings_dir / "index.jsonl"
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

    # Always keep a primary directory per token. Duplicates go under dups/<sha1>/.
    base = _token_dir(cfg, token_l)
    dest_dir = base if sha1 == primary else (base / "dups" / sha1)
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

    # Copy/link the libFuzzer artifact if present.
    for prefix in ("crash", "timeout", "oom", "leak"):
        cand = cfg.artifacts_dir / f"{prefix}-{sha1}"
        if cand.is_file():
            _link_or_copy(cand, dest_dir / cand.name)
            break

    crash_info = _extract_crash_info(excerpt_lines) if excerpt_lines else None
    finding = Finding(
        ts=time.time(),
        token=token_l,
        sha1=sha1,
        source_log=str(source_log),
        source_line=source_line.strip(),
        crash=crash_info,
        excerpt_log=excerpt_name,
    )
    try:
        if not meta_exists:
            meta_path.write_text(json.dumps(asdict(finding), ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            # If an old record exists, fill in crash/excerpt fields opportunistically.
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("excerpt_log") is None:
                meta["excerpt_log"] = excerpt_name
            if meta.get("crash") is None and crash_info is not None:
                meta["crash"] = asdict(crash_info)
            meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    try:
        if not meta_exists:
            with index_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(finding), ensure_ascii=False) + "\n")
    except Exception:
        pass

    try:
        state_path.write_text(
            json.dumps({"token_primary_sha1": token_map, "sha1_token": sha1_map}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except Exception:
        pass


def run_findings_deduper(cfg: Config) -> None:
    """
    Watches <work-dir>/logs for Jazzer findings and groups them by DEDUP_TOKEN.

    For each finding it tries to derive the input SHA-1 either from:
      - `Test unit written to .../<kind>-<sha1>` output (preferred), or
      - `Base64: ...` output (fallback; only when no artifact line exists).

    Reproducers and artifacts are hardlinked (or copied) into:
      <work-dir>/findings/<dedup_token>/          (primary)
      <work-dir>/findings/<dedup_token>/dups/... (duplicates)
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
                _process_line(cfg, st=st, line=line, source_log=path, seen_pairs=seen_pairs)

        time.sleep(0.25)
