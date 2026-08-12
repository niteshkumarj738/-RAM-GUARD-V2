"""
leak_simulator.py

Deliberately leaks memory at a controlled, known rate, so RAM-Guard's
leak-suspect detector can be validated against ground truth instead of
waiting for a real leaky program to show up.

This is a self-test harness, not a security exploit — it only allocates
memory in its own process.

Usage:
    python leak_simulator.py --mb-per-sec 0.6 --duration 90
    (default leaks ~36 MB/min, comfortably above the 25 MB/min config threshold)
"""

import argparse
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def leak(mb_per_sec: float, duration: int):
    print(f"[leak_simulator] PID={__import__('os').getpid()} "
          f"leaking ~{mb_per_sec * 60:.1f} MB/min for {duration}s. "
          f"Point RAM-Guard at this PID/host now.")
    chunks = []
    start = time.time()
    while time.time() - start < duration:
        # allocate ~mb_per_sec worth of memory each second, keep the reference
        # so it can never be garbage collected -> guaranteed monotonic growth
        chunk = bytearray(int(mb_per_sec * 1024 * 1024))
        chunks.append(chunk)
        elapsed = time.time() - start
        total_mb = sum(len(c) for c in chunks) / (1024 * 1024)
        print(f"[leak_simulator] t={elapsed:5.1f}s  total leaked ≈ {total_mb:.1f} MB")
        time.sleep(1)
    print("[leak_simulator] Done. Process will now hold this memory until exit.")
    input("Press Enter to release memory and exit...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Controlled memory leak for validating RAM-Guard")
    parser.add_argument("--mb-per-sec", type=float, default=0.6,
                         help="MB leaked per second (default 0.6 = ~36 MB/min)")
    parser.add_argument("--duration", type=int, default=90, help="Seconds to run")
    args = parser.parse_args()
    leak(args.mb_per_sec, args.duration)
