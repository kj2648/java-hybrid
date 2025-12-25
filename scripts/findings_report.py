#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from jfo.config import Config


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Print a quick, one-screen findings overview.")
    p.add_argument("--work-dir", required=True, help="Work directory root (e.g. ./w2)")
    p.add_argument("--limit", type=int, default=50, help="Max tokens to print (default: 50)")
    args = p.parse_args(argv)

    work_dir = Path(os.path.expanduser(args.work_dir)).resolve()
    cfg = Config(work_dir=work_dir)
    overview_path = cfg.findings_dir / "overview.json"
    if not overview_path.is_file():
        raise SystemExit(f"missing {overview_path} (run the pipeline or `scripts/rebuild_findings.py --work-dir ... --reset`)")

    overview = json.loads(overview_path.read_text(encoding="utf-8"))
    gen = overview.get("time") or "?"
    tokens = overview.get("tokens") or []

    print(f"[findings] work_dir={cfg.work_dir} generated={gen} tokens={len(tokens)}")
    print("")
    print("Tokens (DEDUP_TOKEN):")
    print("  token            first_time                unique_inputs  exception                       top / top2 / top3")
    print("  --------------  ------------------------  ------------  ------------------------------  -------------------")

    n = 0
    for t in tokens:
        if n >= max(0, int(args.limit)):
            break
        token = (t.get("token") or "?")[:14].ljust(14)
        first_time = (t.get("first_time") or "")[:24].ljust(24)
        uniq = str(int(t.get("unique_inputs", 0) or 0)).rjust(12)
        exc_cls = (t.get("exception") or "").splitlines()[0].strip()
        if len(exc_cls) > 60:
            exc_cls = exc_cls[:57] + "..."
        def fmt(file_key: str, line_key: str) -> str:
            tf = (t.get(file_key) or "").strip()
            tl = t.get(line_key)
            return f"{tf}:{int(tl)}" if (tf and isinstance(tl, int)) else tf

        top = " / ".join([s for s in [fmt("top_file", "top_line"), fmt("top2_file", "top2_line"), fmt("top3_file", "top3_line")] if s])
        if len(top) > 70:
            top = top[:67] + "..."
        exc_cls = exc_cls.ljust(30)
        print(f"  {token}  {first_time}  {uniq}  {exc_cls}  {top}")
        n += 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
