#!/usr/bin/env python3
import sys, subprocess
from pathlib import Path

"""
Contract:
  python spf_wrapper.py <seed_file> <out_dir>

You must implement the actual SPF run command so that it:
  - reads seed_file (or uses it to initialize input)
  - generates 0..N new input files under out_dir
"""

def main():
    seed = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # TODO: replace this with your SPF command.
    # Example sketch:
    #   cmd = ["bash", "run_spf.sh", str(seed), str(out_dir)]
    # SPF가 생성한 concrete inputs를 out_dir에 dump하도록 구성해야 함.

    cmd = ["/path/to/run_spf_seed2inputs.sh", str(seed), str(out_dir)]
    rc = subprocess.call(cmd)
    return rc

if __name__ == "__main__":
    sys.exit(main())
