#!/usr/bin/env python3
import sys
import subprocess
from pathlib import Path

"""
Contract:
  python swat_engine.py <seed_file> <out_dir>
"""


def main():
    seed = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["/path/to/run_swat_seed2inputs.sh", str(seed), str(out_dir)]
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
