"""
high_memory_hog.py

Deliberately allocates a large, fixed block of memory to validate the
high-memory-usage detector against a known, reproducible condition.

Usage:
    python high_memory_hog.py --target-percent 20
"""

import argparse
import sys
import time
import psutil

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def hog(target_percent: float, hold_seconds: int):
    total_mb = psutil.virtual_memory().total / (1024 * 1024)
    target_mb = total_mb * (target_percent / 100.0)
    print(f"[high_memory_hog] PID={__import__('os').getpid()} "
          f"allocating {target_mb:.0f} MB (~{target_percent}% of {total_mb:.0f} MB total RAM)")

    block = bytearray(int(target_mb * 1024 * 1024))
    # touch every page so it's actually resident, not just reserved virtual memory
    step = 4096
    for i in range(0, len(block), step):
        block[i] = 1

    print(f"[high_memory_hog] Allocated and touched. Holding for {hold_seconds}s — "
          f"point RAM-Guard at this PID/host now.")
    time.sleep(hold_seconds)
    print("[high_memory_hog] Done.")
    input("Press Enter to release memory and exit...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Controlled high-memory usage for validating RAM-Guard")
    parser.add_argument("--target-percent", type=float, default=20.0,
                         help="Target % of total system RAM to allocate (default 20)")
    parser.add_argument("--hold-seconds", type=int, default=60)
    args = parser.parse_args()
    hog(args.target_percent, args.hold_seconds)
