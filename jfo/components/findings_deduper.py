import base64
import hashlib
import json
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


@dataclass(frozen=True, slots=True)
class Finding:
    ts: float
    token: str
    sha1: str
    source_log: str
    source_line: str


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


class _TailState:
    def __init__(self) -> None:
        self.offset = 0
        self.buf = ""
        self.pending_token: str | None = None
        self.pending_token_ts = 0.0
        self.pending_sha1: str | None = None
        self.pending_sha1_ts = 0.0


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


def _handle_finding(cfg: Config, *, token: str, sha1: str, source_log: Path, source_line: str) -> None:
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
    if source_log.is_file():
        _link_or_copy(source_log, dest_dir / source_log.name)

    finding = Finding(ts=time.time(), token=token_l, sha1=sha1, source_log=str(source_log), source_line=source_line.strip())
    try:
        if not meta_exists:
            meta_path.write_text(json.dumps(asdict(finding), ensure_ascii=False, indent=2), encoding="utf-8")
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
      - `Base64: ...` output (preferred), or
      - `Test unit written to .../<kind>-<sha1>` output (fallback).

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
                now = time.time()
                token = None
                m = _RE_DEDUP_TOKEN.search(line)
                if m:
                    token = m.group(1).lower()
                    # De-dupe the duplicate DEDUP_TOKEN lines printed to stdout+stderr.
                    if st.pending_token == token and (now - st.pending_token_ts) < 1.0:
                        token = None
                    else:
                        st.pending_token = token
                        st.pending_token_ts = now

                sha1 = None
                m_b64 = _RE_BASE64.match(line)
                if m_b64:
                    sha1 = _compute_sha1_from_base64(m_b64.group(1))
                else:
                    m_tu = _RE_TEST_UNIT.search(line)
                    if m_tu:
                        m_sha1 = _RE_ARTIFACT_SHA1.search(m_tu.group(1))
                        if m_sha1:
                            sha1 = m_sha1.group(1).lower()

                if sha1:
                    st.pending_sha1 = sha1.lower()
                    st.pending_sha1_ts = now

                # Pair token and sha1 in either order within a small window.
                if st.pending_token and st.pending_sha1:
                    if (now - st.pending_token_ts) < 15.0 and (now - st.pending_sha1_ts) < 15.0:
                        key = (st.pending_token, st.pending_sha1)
                        if key not in seen_pairs:
                            seen_pairs.add(key)
                            _handle_finding(
                                cfg,
                                token=st.pending_token,
                                sha1=st.pending_sha1,
                                source_log=path,
                                source_line=line,
                            )
                        st.pending_token = None
                        st.pending_sha1 = None

        time.sleep(0.25)
