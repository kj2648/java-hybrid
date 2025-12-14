#!/usr/bin/env python3
import sys, subprocess
from pathlib import Path

"""
Contract:
  python swat_wrapper.py <seed_file> <out_dir>

SWAT도 마찬가지로 seed를 입력으로 주고, 새 inputs를 out_dir에 dump하는
wrapper만 있으면 orchestration은 그대로 동작함.
"""

def main():
    seed = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["/path/to/run_swat_seed2inputs.sh", str(seed), str(out_dir)]
    rc = subprocess.call(cmd)
    return rc

if __name__ == "__main__":
    sys.exit(main())
