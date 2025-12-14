#!/usr/bin/env python3
import sys, subprocess
from datetime import datetime
from pathlib import Path

def main():
    seed = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(str(out_dir / datetime.now().strftime('%Y-%m-%d_%H:%M:%S')), "w") as f:
      f.write(str(seed))


if __name__ == "__main__":
    sys.exit(main())
